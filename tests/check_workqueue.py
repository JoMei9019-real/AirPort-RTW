#!/usr/bin/env python3
"""Run the production workqueue with host locks/threads and deterministic timers.

The timer mock deliberately delivers a stale callback after cancellation. This
does not emulate XNU scheduling or prove hardware sleep/hibernate correctness.
"""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'src/compat/rtw88_compat.c').read_text()
production = source[source.index('static IOLock *work_state_lock;'):
                    source.index('/*  Timer implementation (thread_call)')]
types = (root / 'src/compat/linux/types.h').read_text()
lists = types[types.index('struct list_head {'):types.index('/* hlist */')]
header = (root / 'src/compat/linux/workqueue.h').read_text()
header = '\n'.join(line for line in header.splitlines()
                   if not line.startswith('#include')) + '\n'
pre = r'''
#include <cassert>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <thread>
#include <vector>
using thread_t = std::thread*;
using wait_result_t = int;
using kern_return_t = int;
using thread_call_t = void*;
constexpr int KERN_SUCCESS=0, THREAD_UNINT=0;
struct IOLock {
 std::mutex mutex;
 std::condition_variable changed;
 std::map<void*, unsigned> sleepers;
};
IOLock *IOLockAlloc(){return new IOLock;}
void IOLockFree(IOLock *p){delete p;}
void IOLockLock(IOLock *p){p->mutex.lock();}
void IOLockUnlock(IOLock *p){p->mutex.unlock();}
void IOLockSleep(IOLock *p, void *event, int){
 std::unique_lock<std::mutex> lock(p->mutex,std::adopt_lock);
 ++p->sleepers[event];
 p->changed.wait(lock);
 --p->sleepers[event];
 lock.release();
}
void IOLockWakeup(IOLock *p, void*, bool){p->changed.notify_all();}
void *IOMalloc(size_t n){return std::malloc(n);}
void IOFree(void *p,size_t){std::free(p);}
size_t strlcpy(char *d,const char *s,size_t n){
 size_t length=std::strlen(s);
 if(n){std::memcpy(d,s,length<n?length:n-1);d[length<n?length:n-1]=0;}
 return length;
}
std::vector<thread_t> workers;
int kernel_thread_start(void (*fn)(void*,int),void *p,thread_t *out){
 *out=new std::thread([=]{fn(p,0);});workers.push_back(*out);return 0;
}
void thread_deallocate(thread_t){}
thread_t current_thread(){return nullptr;}
void thread_terminate(thread_t){}
#define container_of(ptr,type,member) ((type*)((char*)(ptr)-offsetof(type,member)))
#define from_timer(var,ptr,member) container_of(ptr,__typeof__(*var),member)
struct timer_list {
 unsigned long expires=0;
 void (*function)(timer_list*)=nullptr;
 thread_call_t call=nullptr;
 bool active=false;
};
unsigned long jiffies=0;
bool timerAllocationFails=false;
void timer_setup(timer_list *t,void(*fn)(timer_list*),unsigned){t->function=fn;}
int mod_timer(timer_list *t,unsigned long deadline){
 t->expires=deadline;t->active=!timerAllocationFails;
 t->call=timerAllocationFails?nullptr:t;return 0;
}
int del_timer(timer_list *t){bool old=t->active;t->active=false;return old;}
int del_timer_sync(timer_list *t){int old=del_timer(t);t->call=nullptr;return old;}
'''
cases = r'''
template<class Predicate> void await(Predicate predicate){
 auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
 while(!predicate()){
  assert(std::chrono::steady_clock::now()<deadline);
  std::this_thread::yield();
 }
}
std::atomic<bool> entered{false},releaseWork{false};
std::atomic<unsigned> calls{0};
void blocked(work_struct*){
 entered=true;await([]{return releaseWork.load();});
}
void counted(work_struct*){++calls;}
bool sleeping(void *event){
 std::lock_guard<std::mutex> lock(work_state_lock->mutex);
 return work_state_lock->sleepers[event]!=0;
}
void joinWorkers(){for(auto p:workers){p->join();delete p;}workers.clear();}
int main(){
 work_state_lock=IOLockAlloc();
 auto a=alloc_ordered_workqueue("control",0);
 auto b=alloc_ordered_workqueue("datapath",0);
 assert(a&&b);
 system_wq=a;
 work_struct running{},queued{};
 INIT_WORK(&running,blocked);INIT_WORK(&queued,counted);
 assert(queue_work(a,&running));await([]{return entered.load();});
 assert(queue_work(a,&queued));assert(!queue_work(a,&queued));
 assert(cancel_work_sync(&queued));assert(calls==0);
 // An executing item cannot migrate to another worker concurrently.
 assert(!queue_work(b,&running));
 std::atomic<bool> canceled{false},flushed{false};
 std::thread canceler([&]{cancel_work_sync(&running);canceled=true;});
 std::thread flusher([&]{flush_workqueue(a);flushed=true;});
 await([&]{return sleeping(&running)&&sleeping(&a->queue);});
 assert(!canceled&&!flushed);assert(!queue_work(a,&running));
 releaseWork=true;canceler.join();flusher.join();
 assert(canceled&&flushed&&!running.executing&&!running.canceling);
 assert(schedule_work(&queued));flush_work(&queued);assert(calls==1);
 delayed_work delayed{};INIT_DELAYED_WORK(&delayed,counted);
 assert(queue_delayed_work(b,&delayed,10));
 assert(!queue_delayed_work(b,&delayed,10));
 assert(cancel_delayed_work_sync(&delayed));
 delayed.timer.function(&delayed.timer); // Already dispatched before cancel.
 flush_workqueue(b);assert(calls==1&&delayed.work.pending==0);
 assert(queue_delayed_work(b,&delayed,10));
 delayed.timer.function(&delayed.timer);flush_work(&delayed.work);
 assert(calls==2&&delayed.work.wq==b);
 assert(queue_delayed_work(b,&delayed,10));
 assert(cancel_delayed_work(&delayed));
 delayed.timer.function(&delayed.timer);flush_workqueue(b);assert(calls==2);
 timerAllocationFails=true;
 assert(!queue_delayed_work(b,&delayed,10)&&!delayed.work.pending);
 timerAllocationFails=false;
 assert(queue_delayed_work(b,&delayed,0));flush_work(&delayed.work);
 assert(calls==3);
 // Synchronous delayed cancellation must also wait for a running callback.
 entered=false;releaseWork=false;
 delayed_work active{};INIT_DELAYED_WORK(&active,blocked);
 assert(queue_delayed_work(b,&active,0));await([]{return entered.load();});
 canceled=false;
 std::thread cancelActive([&]{cancel_delayed_work_sync(&active);canceled=true;});
 await([&]{return sleeping(&active.work);});assert(!canceled);
 releaseWork=true;cancelActive.join();assert(canceled);
 // Exercise FIFO and repeated queue/cancel/reuse without dangling work.
 for(unsigned i=0;i<100;++i){
  assert(queue_work(a,&queued));flush_work(&queued);
 }
 assert(calls==103);
 destroy_workqueue(a);destroy_workqueue(b);joinWorkers();
 system_wq=nullptr;IOLockFree(work_state_lock);work_state_lock=nullptr;
 std::puts("PASS: production workqueue cancellation/flush waits, queue migration, delayed/stale callbacks, timer failure and reuse");
}
'''
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory)
    (path / 'test.cpp').write_text(pre + lists + header + production + cases)
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-pthread',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-g', str(path / 'test.cpp'), '-o', str(path / 'test')],
                   check=True, timeout=60)
    subprocess.run([str(path / 'test')], check=True, timeout=30,
                   env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})

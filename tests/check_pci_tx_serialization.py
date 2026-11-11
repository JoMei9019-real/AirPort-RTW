#!/usr/bin/env python3
"""Run the pinned PCI TX function with deterministic concurrent producers.
Negative control reproduces the hole; patched code covers errors and wraparound.
DMA/RF and macOS scheduling are mocked; this is not a hardware stability test.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile
root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prepare_pci', root/'scripts/prepare-pci.py')
patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)
# Generated PCI source must find the driver's quoted pci.h before linux/pci.h.
makefile = (root/'Makefile').read_text()
assert '$(DRIVER_CFLAGS) -iquote $(LINUX_SRC) -c $< -o $@' in makefile
source = Path(os.environ.get('RTW88_PCI_SOURCE', str(root/'rtw88-stable/drivers/net/wireless/realtek/rtw88/pci.c'))).read_text()
def function(s):
    a=s.index('static int rtw_pci_tx_write_data(')
    return s[a:s.index('\nstatic int rtw_pci_write_data_rsvd_page',a)]
pre=r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <cstdio>
using u8=uint8_t;using u16=uint16_t;using u32=uint32_t;using dma_addr_t=uintptr_t;
enum rtw_tx_queue_type{RTW_TX_QUEUE_BE,RTW_TX_QUEUE_BCN};
constexpr int DMA_TO_DEVICE=0,RTK_PCI_TXBD_OWN_OFFSET=15;
struct rtw_pci_tx_buffer_desc{u16 psb_len,buf_size;u32 dma;};
struct rtw_pci_tx_data{dma_addr_t dma;u32 sn;};
struct sk_buff{u32 len=126;u8 bytes[256]{};rtw_pci_tx_data data{};};
struct rtw_tx_pkt_info{u32 qsel=0,sn=0;};
struct rtw_chip_info{u32 tx_pkt_desc_sz=48,tx_buf_desc_sz=16;};
struct Ring{u32 wp=0,rp=0,len=256;};
struct Queue{u32 count=0;};
struct rtw_pci_tx_ring{Ring r;Queue queue;rtw_pci_tx_buffer_desc descriptors[256][2]{};};
struct Pdev{int dev=0;};
struct rtw_pci{rtw_pci_tx_ring tx_rings[2];Pdev *pdev;std::mutex irq_lock;u32 tx_queued[1]{};};
struct rtw_dev{void*priv;const rtw_chip_info*chip;};
std::mutex schedule;std::condition_variable cv;int selected=0;bool firstCompleted=false,controlled=true,mapFailed=false;thread_local int actor=0;thread_local bool held=false;
u32 avail_desc(u32 wp,u32 rp,u32 len){return (rp+len-wp-1)%len;}
void rtw_pci_release_rsvd_page(rtw_pci*,rtw_pci_tx_ring*){}
u8*skb_push(sk_buff*s,u32 n){s->len+=n;return s->bytes;}
u32 rtw_pci_get_tx_qsel(sk_buff*,rtw_tx_queue_type){return 0;}
void rtw_tx_fill_tx_desc(rtw_dev*,rtw_tx_pkt_info*,sk_buff*){}
dma_addr_t dma_map_single(int*,u8*,u32,int){return 0x1000+actor*0x1000;}
bool dma_mapping_error(int*,dma_addr_t){return mapFailed;}
rtw_pci_tx_buffer_desc*get_tx_buffer_desc(rtw_pci_tx_ring*r,u32){
 if(held || !controlled)return r->descriptors[r->r.wp];
 std::unique_lock<std::mutex>l(schedule);
 auto*p=r->descriptors[r->r.wp]; // same slot selection as production helper
 ++selected;cv.notify_all();
 if(actor==0)cv.wait(l,[]{return selected==2;});
 else cv.wait(l,[]{return firstCompleted;});
 return p;
}
rtw_pci_tx_data*rtw_pci_get_tx_data(sk_buff*s){return &s->data;}
u16 cpu_to_le16(u16 x){return x;}u32 cpu_to_le32(u32 x){return x;}
void spin_lock_bh(std::mutex*m){m->lock();held=true;}
void spin_unlock_bh(std::mutex*m){held=false;m->unlock();if(actor==0){std::lock_guard<std::mutex>l(schedule);firstCompleted=true;cv.notify_all();}}
void skb_queue_tail(Queue*q,sk_buff*){++q->count;}
void set_bit(int n,u32*p){*p|=1u<<n;}
'''
# production uses skb->data pointer, represented separately from tx bookkeeping
pre=pre.replace('rtw_pci_tx_data data{};', 'u8*data=bytes;rtw_pci_tx_data bookkeeping{};').replace('return &s->data;', 'return &s->bookkeeping;')

post=r'''
int main(){Pdev p;rtw_pci pci;pci.pdev=&p;rtw_chip_info chip;rtw_dev dev{&pci,&chip};sk_buff a,b;rtw_tx_pkt_info ia,ib;int ra=-1,rb=-1;
 std::thread t0([&]{actor=0;ra=rtw_pci_tx_write_data(&dev,&ia,&a,RTW_TX_QUEUE_BE);});
 std::thread t1([&]{actor=1;rb=rtw_pci_tx_write_data(&dev,&ib,&b,RTW_TX_QUEUE_BE);});
 t0.join();t1.join();auto&r=pci.tx_rings[0];assert(ra==0&&rb==0);assert(r.r.wp==2&&r.queue.count==2);
#ifdef NEGATIVE_CONTROL
 assert(r.descriptors[0][0].dma==0x2000&&r.descriptors[1][0].dma==0);
 puts("PASS: negative control reproduces two submissions overwriting one slot");
#else
 assert(r.descriptors[0][0].dma && r.descriptors[1][0].dma);
 assert(r.descriptors[0][0].dma!=r.descriptors[1][0].dma);
 controlled=false;
 // Both early errors must release the producer lock and publish nothing.
 r.r.wp=255;r.r.rp=0;u32 queued=r.queue.count;sk_buff full;
 assert(rtw_pci_tx_write_data(&dev,&ia,&full,RTW_TX_QUEUE_BE)==-ENOSPC&&!held);
 assert(r.r.wp==255&&r.queue.count==queued&&full.len==126);
 r.r.rp=254;mapFailed=true;sk_buff failed;
 assert(rtw_pci_tx_write_data(&dev,&ia,&failed,RTW_TX_QUEUE_BE)==-EBUSY&&!held);
 assert(r.r.wp==255&&r.queue.count==queued);mapFailed=false;
 // Wrap the ring and verify successful submission after both error paths.
 sk_buff wrap;assert(!rtw_pci_tx_write_data(&dev,&ia,&wrap,RTW_TX_QUEUE_BE));
 assert(r.r.wp==0&&r.descriptors[255][0].dma);
 // Reserved beacon slot keeps OWN semantics and does not advance its index.
 sk_buff beacon;assert(!rtw_pci_tx_write_data(&dev,&ia,&beacon,RTW_TX_QUEUE_BCN));
 auto&bc=pci.tx_rings[1];assert(bc.r.wp==0&&bc.queue.count==1&&(bc.descriptors[0][0].psb_len&0x8000));
 // Concurrent scan/data-like producers must fill every slot exactly once.
 r.r.wp=r.r.rp=0;r.queue.count=0;memset(r.descriptors,0,sizeof(r.descriptors));
 std::thread producers[32];
 for(int i=0;i<32;++i)producers[i]=std::thread([&,i]{actor=i+1;sk_buff skb;rtw_tx_pkt_info info;assert(!rtw_pci_tx_write_data(&dev,&info,&skb,RTW_TX_QUEUE_BE));});
 for(auto&t:producers){t.join();}
 assert(r.r.wp==32&&r.queue.count==32);
 bool seen[33]{};
 for(int i=0;i<32;++i){u32 owner=r.descriptors[i][0].dma/0x1000-1;assert(owner>=1&&owner<=32&&!seen[owner]);seen[owner]=true;}
 puts("PASS: serialized PCI producers, no descriptor holes, full/mapping errors, ring wrap and beacon ownership");
#endif
}
'''
with tempfile.TemporaryDirectory() as d:
    p=Path(d)
    for name,code,flags in [('negative',source,['-DNEGATIVE_CONTROL']),('fixed',patch.prepare(source),[])]:
        (p/'test.cpp').write_text(pre+function(code)+post)
        subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-pthread','-Wall','-Wextra',*flags,str(p/'test.cpp'),'-o',str(p/name)],check=True)
        subprocess.run([str(p/name)],check=True,timeout=20)
    try:
        patch.prepare(source+'\n')
        raise AssertionError('Changed dependency was silently accepted')
    except ValueError:
        pass
print('PASS: build preparation rejects an unreviewed dependency revision')

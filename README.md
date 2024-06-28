Dopamine越狱iOS15.8.1，IPhone6s；
1，查看unma -a 获取xnu版本，

2，下载源码xnu-8020.241.42，获取 proc 结构

3，通过计算p_proc_ro的地址，获取p_uniqueid来判断对应的p_list;
    // 计算p_proc_ro的地址
            uint64_t p_proc_ro_addr = proc2 + offsetof(struct proc, p_proc_ro);
           // 读取p_proc_ro的值
            uint64_t proc_ro_addr = kread64(p_proc_ro_addr);

            // 计算p_uniqueid的地址
            uint64_t p_uniqueid_addr = proc_ro_addr + offsetof(struct proc_ro, p_uniqueid);
            // 读取p_uniqueid的值
            uint64_t p_uniqueid_value = kread64(p_uniqueid_addr);
            // 打印进程地址和p_uniqueid值
            // printf("[i] Process at 0x%llx has unique ID: %llu\n", proc2, p_uniqueid_value);
            
4,获取到pid对应pro地址来获取p_lflag，
因为通过proc 结构异常，通过kernelcache.release.iPhone8,1解析获取ptrace 地址来判断p_lflag偏移


对照源码可以知道p_lflag偏移是0x268


5，最后就通过lflagoffset获取了lflag数据


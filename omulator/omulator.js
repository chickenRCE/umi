// var hex = (n) => { return "0x" + n.toString(16) }
// var lohi = (lo, hi) => { return hi * 0x100000000 + ((lo+0x100000000)%0x100000000) }
// var chr = (c) => { return String.fromCharCode(c) }
// var ord = (s) => { return s.charCodeAt(0) }
// var u8 = (s) => { return s[0] }
// var u16 = (s) => { return s[0] + (s[1] << 8) }
// var u32 = (s) => { return s[0] + (s[1] << 8) + (s[2] << 16) + (s[3] << 24) }
// var u64 = (s) => { return s[0] + (s[1] << 8) + (s[2] << 16) + (s[3] << 24)
//                             + (s[4] << 32) + (s[5] << 40) + (s[6] << 48) + (s[7] << 56) }
// var p8 = (n) => { return [chr(n)] }
// var p16 = (n) => { return [n & 0xff, (n >> 8) & 0xff] }
// var p32 = (n) => { return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff] }
// var p64 = (n) => { return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff,
//                             (n >> 32) & 0xff, (n >> 40) & 0xff, (n >> 48) & 0xff, (n >> 56) & 0xff] }


class OmulatorX86 {
    constructor(asm, input) {
        asm = asm.replace(/\bdb\b/g, " .byte")
        asm = asm.replace(/\bdh\b/g, " .value")
        asm = asm.replace(/\bdd\b/g, " .long")
        asm = asm.replace(/\bdq\b/g, " .quad")

        this.a = new ks.Keystone(ks.ARCH_X86, ks.MODE_64)
        this.a.option(ks.OPT_SYNTAX, ks.OPT_SYNTAX_INTEL)
        this.d = new cs.Capstone(cs.ARCH_X86, cs.MODE_64);

        let code_split = asm.split('\n')
        this.code_line_map = {}
        this.hlt_line = 0

        this.code = this.asm(asm)

        let disasm = this.disasm(this.code)
        let disasm_i = 0
        for (var i = 0; i < code_split.length; ++i) {
            let ins = disasm[disasm_i]
            let line = code_split[i].trim()
            if (line.length > 0 && line[0] != ';' && line[0] != '.' && line.slice(-1) != ':') {
                disasm_i++
                this.code_line_map[ins.address] = i + 1
            }
            if (ins.mnemonic == 'hlt') {
                this.hlt_line = i + 1
                this.hlt_addr = ins.address
            }

            if (disasm_i == disasm.length) break
        }

        if (this.hlt_line == 0) {
            this.hlt_line = code_split.length + 1
            this.hlt_addr = 0x400000 + this.code.length + 1
            this.code_line_map[this.hlt_addr - 1] = this.hlt_line
        }

        this.input = input
        // let disasm = this.disasm(code)

        // console.log(asm)
        // console.log(disasm)

        // this.verify_asm(asm, disasm)

        this.setup_mmap()
        this.setup_hooks()
        this.reset_regs()
        this.reset_stack()
        this.reset_mmio()
    }

    verify_asm(asm, disasm) {
        asm = asm.split(";").map(s => {return s.trim()})
        asm.pop()

        let errored_lines = []
        let disasm_i = 0
        for (let i in asm) {
            let asm_ins = asm[i]
            let disasm_ins = `${disasm[disasm_i].mnemonic} ${disasm[disasm_i].op_str}`

            asm_ins = asm_ins.split(" ").filter(s => {return s.length > 0}).join(" ")
            disasm_ins = disasm_ins.split(" ").filter(s => {return s.length > 0}).join(" ")
            if (asm_ins.localeCompare(disasm_ins) == 0)
                disasm_i += 1
            else {
                // console.log(asm_ins)
                // console.log(disasm_ins)
                errored_lines.push(i)
            }
        }

        // console.log(errored_lines)
    }

    setup_mmap() {
        let page_size = (Math.floor(this.code.length / 4096) + 1) * 4096
        // this.code = [0x41, 0x4a]

        this.text_base = 0x400000
        this.text_end = this.text_base + this.code.length

        this.unicorn = new uc.Unicorn(uc.ARCH_X86, uc.MODE_64)
        this.unicorn.mem_map(this.text_base, page_size, uc.PROT_ALL);
        this.unicorn.mem_map(0x10000, 0x2000, uc.PROT_ALL);
        this.unicorn.mem_map(0xf000, 0x1000, uc.PROT_ALL);
        this.unicorn.mem_map(0x1000, 0x1000, uc.PROT_ALL);
        this.unicorn.mem_map(0x2000, 0x1000, uc.PROT_ALL);
        this.unicorn.mem_write(this.text_base, this.code)

        this.set_reg("rsp", 0x11000)
        this.set_reg("rbp", 0x11000)
    }

    setup_hooks() {
        this.setup_hook_mem_fetch_unmapped();
        this.setup_hook_mem_read_unmapped();
        this.setup_hook_mem_write_unmapped();
    }

    setup_hook_mem_fetch_unmapped() {
        this.unicorn.hook_add(uc.HOOK_MEM_FETCH_UNMAPPED,
            (emu, type, addr_lo, addr_hi, size, value_lo, value_hi, user_data) => {
                console.log(hex(addr_lo), hex(addr_hi))
                console.log(hex(value_lo), hex(value_hi))
                return true
        })
    }

    setup_hook_mem_read_unmapped() {
        this.unicorn.hook_add(uc.HOOK_MEM_READ_UNMAPPED,
            (emu, type, addr_lo, addr_hi, size, value_lo, value_hi, user_data) => {
                console.log(hex(addr_lo), hex(addr_hi))
                return true
        })
    }

    setup_hook_mem_write_unmapped() {
        this.unicorn.hook_add(uc.HOOK_MEM_WRITE_UNMAPPED,
            (emu, type, addr_lo, addr_hi, size, value_lo, value_hi, user_data) => {
                let addr = lohi(addr_lo, addr_hi)
                let value = lohi(value_lo, value_hi)
                emu.mem_write(addr, p64(value))
                console.log(hex(value >>> 32))
                console.log(p64(value))
                console.log(hex(u64(emu.mem_read(addr, 8))))
        })
    }

    reg_name_to_uc(reg) {
        return {
            'eax': uc.X86_REG_EAX,
            'ebx': uc.X86_REG_EBX,
            'ecx': uc.X86_REG_ECX,
            'edx': uc.X86_REG_EDX,
            'edi': uc.X86_REG_EDI,
            'esi': uc.X86_REG_ESI,
            'ebp': uc.X86_REG_EBP,
            'esp': uc.X86_REG_ESP,
            'eip': uc.X86_REG_EIP,
            'rax': uc.X86_REG_RAX,
            'rbx': uc.X86_REG_RBX,
            'rcx': uc.X86_REG_RCX,
            'rdx': uc.X86_REG_RDX,
            'rdi': uc.X86_REG_RDI,
            'rsi': uc.X86_REG_RSI,
            'r8': uc.X86_REG_R8,
            'r9': uc.X86_REG_R9,
            'r10': uc.X86_REG_R10,
            'r11': uc.X86_REG_R11,
            'r12': uc.X86_REG_R12,
            'r13': uc.X86_REG_R13,
            'r14': uc.X86_REG_R14,
            'r15': uc.X86_REG_R15,
            'rbp': uc.X86_REG_RBP,
            'rsp': uc.X86_REG_RSP,
            'rip': uc.X86_REG_RIP
        }[reg]
    }

    get_reg(reg) {
        return this.get_regs()[reg]
    }

    get_regs() {
        return {
            // 'eax': this.unicorn.reg_read_i32(uc.X86_REG_EAX),
            // 'ebx': this.unicorn.reg_read_i32(uc.X86_REG_EBX),
            // 'ecx': this.unicorn.reg_read_i32(uc.X86_REG_ECX),
            // 'edx': this.unicorn.reg_read_i32(uc.X86_REG_EDX),
            // 'edi': this.unicorn.reg_read_i32(uc.X86_REG_EDI),
            // 'esi': this.unicorn.reg_read_i32(uc.X86_REG_ESI),
            // 'ebp': this.unicorn.reg_read_i32(uc.X86_REG_EBP),
            // 'esp': this.unicorn.reg_read_i32(uc.X86_REG_ESP),
            // 'eip': this.unicorn.reg_read_i32(uc.X86_REG_EIP),
            'rax': this.unicorn.reg_read_i64(uc.X86_REG_RAX),
            'rbx': this.unicorn.reg_read_i64(uc.X86_REG_RBX),
            'rcx': this.unicorn.reg_read_i64(uc.X86_REG_RCX),
            'rdx': this.unicorn.reg_read_i64(uc.X86_REG_RDX),
            'rdi': this.unicorn.reg_read_i64(uc.X86_REG_RDI),
            'rsi': this.unicorn.reg_read_i64(uc.X86_REG_RSI),
            'r8': this.unicorn.reg_read_i64(uc.X86_REG_R8),
            'r9': this.unicorn.reg_read_i64(uc.X86_REG_R9),
            'r10': this.unicorn.reg_read_i64(uc.X86_REG_R10),
            'r11': this.unicorn.reg_read_i64(uc.X86_REG_R11),
            'r12': this.unicorn.reg_read_i64(uc.X86_REG_R12),
            'r13': this.unicorn.reg_read_i64(uc.X86_REG_R13),
            'r14': this.unicorn.reg_read_i64(uc.X86_REG_R14),
            'r15': this.unicorn.reg_read_i64(uc.X86_REG_R15),
            'rbp': this.unicorn.reg_read_i64(uc.X86_REG_RBP),
            'rsp': this.unicorn.reg_read_i64(uc.X86_REG_RSP),
            'rip': this.unicorn.reg_read_i64(uc.X86_REG_RIP)
        }
    }

    set_reg(reg, value) {
        var reg_uc = this.reg_name_to_uc(reg)
        this.unicorn.reg_write_i64(reg_uc, value)
    }

    reset_regs(inits) {
        this.set_reg("rax", 0)
        this.set_reg("rbx", 0)
        this.set_reg("rcx", 0)
        this.set_reg("rdx", 0)
        this.set_reg("rdi", 0)
        this.set_reg("rsi", 0)
        this.set_reg("r8", 0)
        this.set_reg("r9", 0)
        this.set_reg("r10", 0)
        this.set_reg("r11", 0)
        this.set_reg("r12", 0)
        this.set_reg("r13", 0)
        this.set_reg("r14", 0)
        this.set_reg("r15", 0)
        this.set_reg("rsp", 0xff00)
        this.set_reg("rbp", 0xff00)
        this.set_reg("rip", 0x400000)

        for (const reg in inits) {
            this.set_reg(reg, inits[reg])
        }
    }

    reset_stack() {
        for (var i = 0xf000; i <= 0xffff; i += 8)
            this.write_mem(i, [0,0,0,0,0,0,0,0])
    }

    reset_mmio() {
        for (var i = 0x1000; i <= 0x1fff; i += 8)
            this.write_mem(i, [0,0,0,0,0,0,0,0])
        for (var i = 0x2000; i <= 0x2fff; i += 8)
            this.write_mem(i, [0,0,0,0,0,0,0,0])

        this.write_mem(0x1000, this.input)
    }

    read_mem(addr, size) {
        return this.unicorn.mem_read(addr, size)
    }

    write_mem(addr, data) {
        this.unicorn.mem_write(addr, data)
    }

    step(n) {
        let rip = this.get_reg("rip")
        this.unicorn.emu_start(rip, this.text_end, 0, n)
    }

    run() {
        let rip = this.get_reg("rip")
        this.unicorn.emu_start(rip, this.hlt_addr - 1, 0, 0)
    }

    asm(asm) {
        return this.a.asm(asm)
    }

    disasm(code) {
        return this.d.disasm(code, 0x400000)
    }
}

// var OmulatorMain = () => {
//     let assembly = "inc rax; dec rbx;"
//     assembly = assembly.split(";").map(s => {return s.trim()}).filter(s => {return s.length > 0}).join(";\n") + ";"
//     omulator = new OmulatorX86(assembly)

//     omulator.set_reg("rip", 0x400000)
//     omulator.run()
//     console.log(omulator.get_regs())
// }

// MUnicornReady(OmulatorMain)

// export default OmulatorMain

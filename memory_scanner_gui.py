#!/usr/bin/env python3
"""
memory_scanner_gui.py
======================
Memory scanner + pointer scanner แนวคิดเดียวกับ Cheat Engine พร้อม GUI (tkinter)
รันบน Windows เท่านั้น (ใช้ WinAPI: OpenProcess, ReadProcessMemory, WriteProcessMemory,
VirtualQueryEx, EnumProcessModulesEx)

ข้อควรระวัง:
- ต้องรันด้วยสิทธิ์ Administrator
- ใช้ได้กับ process ที่คุณมีสิทธิ์เข้าถึง/ทดสอบเท่านั้น
- Pointer scan ในไฟล์นี้เป็นเวอร์ชันย่อ (educational) ไม่ได้ optimize เท่า Cheat Engine จริง
  ซึ่งใช้ driver ระดับ kernel และโครงสร้างข้อมูลพิเศษเพื่อความเร็ว — เวอร์ชันนี้อาจช้า
  ถ้า process มีหน่วยความจำเยอะ หรือตั้ง max_level/max_offset สูงเกินไป

ติดตั้ง dependency ก่อนใช้งาน:
    pip install psutil
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
import sys
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox

try:
    import psutil
except ImportError:
    print("ต้องติดตั้ง psutil ก่อน: pip install psutil")
    sys.exit(1)

# ---------------------------------------------------------------------------
# WinAPI constants & struct
# ---------------------------------------------------------------------------
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008

MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
READABLE_PAGE_MASK = 0xFFFFFFFF ^ (PAGE_NOACCESS | PAGE_GUARD)

LIST_MODULES_ALL = 0x03
MAX_REGION_READ = 10 * 1024 * 1024

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t,
]

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]

psapi.EnumProcessModulesEx.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE),
    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
]
psapi.EnumProcessModulesEx.restype = wintypes.BOOL

psapi.GetModuleBaseNameW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
psapi.GetModuleBaseNameW.restype = wintypes.DWORD

psapi.GetModuleInformation.argtypes = [
    wintypes.HANDLE, wintypes.HMODULE, ctypes.POINTER(MODULEINFO), wintypes.DWORD,
]
psapi.GetModuleInformation.restype = wintypes.BOOL

VALUE_TYPES = {
    "int32": ("<i", 4),
    "int64": ("<q", 8),
    "float": ("<f", 4),
    "double": ("<d", 8),
}


# ---------------------------------------------------------------------------
# Core: เปิด process / อ่าน-เขียนหน่วยความจำ / enumerate regions & modules
# ---------------------------------------------------------------------------
def open_process(pid: int):
    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
    handle = kernel32.OpenProcess(access, False, pid)
    if not handle:
        raise OSError(
            f"เปิด process PID={pid} ไม่สำเร็จ (error {ctypes.get_last_error()}). "
            "ลองรันโปรแกรมนี้แบบ Administrator"
        )
    return handle


def read_memory(handle, address: int, size: int):
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), buf, size, ctypes.byref(bytes_read))
    if not ok or bytes_read.value != size:
        return None
    return buf.raw


def write_memory(handle, address: int, data: bytes) -> bool:
    bytes_written = ctypes.c_size_t(0)
    ok = kernel32.WriteProcessMemory(handle, ctypes.c_void_p(address), data, len(data), ctypes.byref(bytes_written))
    return bool(ok) and bytes_written.value == len(data)


def enumerate_readable_regions(handle):
    regions = []
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    max_address = 0x7FFFFFFFFFFF

    while address < max_address:
        result = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if result == 0:
            break
        if mbi.State == MEM_COMMIT and (mbi.Protect & READABLE_PAGE_MASK) and mbi.Protect != 0:
            size = min(mbi.RegionSize, MAX_REGION_READ)
            regions.append((mbi.BaseAddress or 0, size))
        address = (mbi.BaseAddress or 0) + mbi.RegionSize
        if mbi.RegionSize == 0:
            break
    return regions


def get_modules(handle):
    """คืน list ของ (module_name, base_address, size) ของ process — ใช้เป็นจุด 'static' สำหรับ pointer chain"""
    arr_size = 1024
    h_mods = (wintypes.HMODULE * arr_size)()
    needed = wintypes.DWORD()
    if not psapi.EnumProcessModulesEx(handle, h_mods, ctypes.sizeof(h_mods), ctypes.byref(needed), LIST_MODULES_ALL):
        return []

    count = min(arr_size, needed.value // ctypes.sizeof(wintypes.HMODULE))
    modules = []
    for i in range(count):
        hmod = h_mods[i]
        name_buf = ctypes.create_unicode_buffer(260)
        psapi.GetModuleBaseNameW(handle, hmod, name_buf, 260)
        info = MODULEINFO()
        psapi.GetModuleInformation(handle, hmod, ctypes.byref(info), ctypes.sizeof(info))
        modules.append((name_buf.value, info.lpBaseOfDll or 0, info.SizeOfImage))
    return modules


def find_module_containing(modules, address):
    for name, base, size in modules:
        if base <= address < base + size:
            return name, base, size
    return None


# ---------------------------------------------------------------------------
# Value scan (first scan / next scan) — เหมือนเวอร์ชัน CLI เดิม
# ---------------------------------------------------------------------------
def first_scan(handle, value, value_type_name, log=None):
    fmt, size = VALUE_TYPES[value_type_name]
    target_bytes = struct.pack(fmt, value)
    regions = enumerate_readable_regions(handle)
    found = []

    for i, (base, region_size) in enumerate(regions):
        data = read_memory(handle, base, region_size)
        if data is None:
            continue
        for offset in range(0, len(data) - size + 1, size):
            if data[offset:offset + size] == target_bytes:
                found.append(base + offset)
        if log and i % 50 == 0:
            log(f"สแกนแล้ว {i}/{len(regions)} regions, เจอ {len(found)} address")

    return found


def read_current_values(handle, addresses, value_type_name):
    fmt, size = VALUE_TYPES[value_type_name]
    values = {}
    for addr in addresses:
        data = read_memory(handle, addr, size)
        if data is not None:
            values[addr] = struct.unpack(fmt, data)[0]
    return values


def next_scan(handle, addresses, value_type_name, mode, old_values=None, new_value=None):
    fmt, size = VALUE_TYPES[value_type_name]
    result = []
    for addr in addresses:
        data = read_memory(handle, addr, size)
        if data is None:
            continue
        current = struct.unpack(fmt, data)[0]
        if mode == "exact":
            if current == new_value:
                result.append(addr)
        else:
            old = old_values.get(addr) if old_values else None
            if old is None:
                continue
            if mode == "changed" and current != old:
                result.append(addr)
            elif mode == "unchanged" and current == old:
                result.append(addr)
            elif mode == "increased" and current > old:
                result.append(addr)
            elif mode == "decreased" and current < old:
                result.append(addr)
    return result


# ---------------------------------------------------------------------------
# Pointer scan (reverse search) — หา static chain: module+offset -> ... -> target
# ---------------------------------------------------------------------------
def reverse_search_pointers(handle, regions, target_value, max_offset, pointer_size, cap=20000):
    """
    หา address X ทั้งหมดที่ค่า pointer ซึ่งเก็บอยู่ที่ X (เรียกว่า P) ทำให้
    0 <= target_value - P <= max_offset
    คืนค่าเป็น list ของ (address_X, offset) โดย offset = target_value - P
    """
    fmt = "<Q" if pointer_size == 8 else "<I"
    results = []

    for base, size in regions:
        data = read_memory(handle, base, size)
        if data is None:
            continue
        for off in range(0, len(data) - pointer_size + 1, pointer_size):
            p = struct.unpack_from(fmt, data, off)[0]
            if p == 0:
                continue
            diff = target_value - p
            if 0 <= diff <= max_offset:
                results.append((base + off, diff))
                if len(results) >= cap:
                    return results
    return results


def pointer_scan(handle, modules, regions, target_address, max_level=3, max_offset=0x800,
                  pointer_size=8, frontier_cap=2000, log=None):
    """
    คืนค่า list ของ chain ที่เจอ แต่ละ chain เป็น dict:
      {"module": ชื่อ dll/exe, "module_offset": offset จาก module base,
       "offsets": [offset1, offset2, ..., offsetN]}  (เรียงจาก module ไปหา target)
    การอ่านค่าจริงตอนใช้งาน: addr = module_base + module_offset
                             วนซ้ำ: addr = read_pointer(addr) + offsets[i]
                             จนถึง offsets ตัวสุดท้าย -> ได้ target_address
    """
    chains = []
    # level 0: หา address ที่ชี้ตรงมาที่ target_address
    frontier = reverse_search_pointers(handle, regions, target_address, max_offset, pointer_size)
    frontier = frontier[:frontier_cap]
    # แต่ละ entry: (offsets_so_far จากปลายทางย้อนขึ้นไป, address_ปัจจุบันที่เป็น pointer field)
    current_level = [([off], addr) for addr, off in frontier]

    for level in range(max_level):
        if log:
            log(f"pointer scan ระดับ {level + 1}/{max_level}: มี {len(current_level)} candidate")
        next_level = []
        for offsets_so_far, addr in current_level:
            mod = find_module_containing(modules, addr)
            if mod:
                mod_name, mod_base, _ = mod
                chains.append({
                    "module": mod_name,
                    "module_offset": addr - mod_base,
                    "offsets": list(reversed(offsets_so_far)),
                })
                continue
            if level == max_level - 1:
                continue
            higher = reverse_search_pointers(handle, regions, addr, max_offset, pointer_size)
            for haddr, hoffset in higher[:frontier_cap]:
                next_level.append((offsets_so_far + [hoffset], haddr))
        current_level = next_level[:frontier_cap]
        if not current_level:
            break

    return chains


def resolve_pointer_chain(handle, module_base, module_offset, offsets, pointer_size=8):
    """อ่านค่า address จริงตอนนี้จาก chain (ใช้ตอนโปรแกรมเป้าหมายรันใหม่ address เปลี่ยนไปแล้ว)"""
    fmt = "<Q" if pointer_size == 8 else "<I"
    addr = module_base + module_offset
    for i, off in enumerate(offsets):
        if i < len(offsets) - 1:
            data = read_memory(handle, addr, pointer_size)
            if data is None:
                return None
            addr = struct.unpack(fmt, data)[0] + off
        else:
            addr = addr + off if i == 0 and len(offsets) == 1 else addr
    return addr


# ---------------------------------------------------------------------------
# GUI (tkinter)
# ---------------------------------------------------------------------------
class MemoryScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Memory Scanner (Cheat Engine concept) - Windows only")
        self.root.geometry("780x600")

        self.handle = None
        self.pid = None
        self.modules = []
        self.addresses = []
        self.old_values = {}
        self.msg_queue = queue.Queue()

        self._build_ui()
        self._poll_queue()

    # ---------------- UI layout ----------------
    def _build_ui(self):
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill="x")

        ttk.Label(top, text="Process:").grid(row=0, column=0, sticky="w")
        self.process_combo = ttk.Combobox(top, width=50, state="readonly")
        self.process_combo.grid(row=0, column=1, columnspan=3, sticky="w", padx=4)
        ttk.Button(top, text="รีเฟรชรายชื่อ", command=self.refresh_processes).grid(row=0, column=4, padx=4)
        ttk.Button(top, text="เปิด process", command=self.attach_process).grid(row=0, column=5, padx=4)

        ttk.Label(top, text="ชนิดค่า:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.type_combo = ttk.Combobox(top, values=list(VALUE_TYPES.keys()), width=10, state="readonly")
        self.type_combo.set("int32")
        self.type_combo.grid(row=1, column=1, sticky="w", pady=(6, 0))

        ttk.Label(top, text="ค่าที่หา:").grid(row=1, column=2, sticky="w", pady=(6, 0))
        self.value_entry = ttk.Entry(top, width=15)
        self.value_entry.grid(row=1, column=3, sticky="w", pady=(6, 0))
        ttk.Button(top, text="First Scan", command=self.do_first_scan).grid(row=1, column=4, pady=(6, 0))

        ttk.Label(top, text="Next scan mode:").grid(row=2, column=0, sticky="w", pady=(6, 0))
        self.mode_combo = ttk.Combobox(
            top, values=["exact", "changed", "unchanged", "increased", "decreased"], width=12, state="readonly"
        )
        self.mode_combo.set("exact")
        self.mode_combo.grid(row=2, column=1, sticky="w", pady=(6, 0))
        ttk.Button(top, text="Next Scan", command=self.do_next_scan).grid(row=2, column=4, pady=(6, 0))

        # ผลลัพธ์
        mid = ttk.Frame(self.root, padding=8)
        mid.pack(fill="both", expand=True)
        ttk.Label(mid, text="ผลลัพธ์ (address = value):").pack(anchor="w")
        self.result_list = tk.Listbox(mid, height=15)
        self.result_list.pack(fill="both", expand=True, side="left")
        scrollbar = ttk.Scrollbar(mid, command=self.result_list.yview)
        scrollbar.pack(side="left", fill="y")
        self.result_list.config(yscrollcommand=scrollbar.set)

        # เขียนค่า / pointer scan
        bottom = ttk.Frame(self.root, padding=8)
        bottom.pack(fill="x")
        ttk.Label(bottom, text="เขียนค่าใหม่ให้ address ที่เลือก:").grid(row=0, column=0, sticky="w")
        self.write_entry = ttk.Entry(bottom, width=15)
        self.write_entry.grid(row=0, column=1, padx=4)
        ttk.Button(bottom, text="Write Value", command=self.do_write).grid(row=0, column=2, padx=4)
        ttk.Button(bottom, text="Pointer Scan สำหรับ address ที่เลือก...", command=self.open_pointer_scan_dialog).grid(
            row=0, column=3, padx=12
        )

        # log
        self.log_text = tk.Text(self.root, height=6, state="disabled", bg="#111", fg="#0f0")
        self.log_text.pack(fill="x", padx=8, pady=(0, 8))

        self.refresh_processes()

    def log(self, msg):
        self.msg_queue.put(msg)

    def _poll_queue(self):
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                self.log_text.config(state="normal")
                self.log_text.insert("end", msg + "\n")
                self.log_text.see("end")
                self.log_text.config(state="disabled")
        except queue.Empty:
            pass
        self.root.after(150, self._poll_queue)

    # ---------------- Process ----------------
    def refresh_processes(self):
        procs = sorted(psutil.process_iter(["pid", "name"]), key=lambda p: (p.info["name"] or "").lower())
        self._proc_list = [(p.info["pid"], p.info["name"]) for p in procs]
        self.process_combo["values"] = [f"{pid} - {name}" for pid, name in self._proc_list]

    def attach_process(self):
        sel = self.process_combo.get()
        if not sel:
            messagebox.showwarning("แจ้งเตือน", "เลือก process ก่อน")
            return
        pid = int(sel.split(" - ")[0])
        try:
            self.handle = open_process(pid)
            self.pid = pid
            self.modules = get_modules(self.handle)
            self.log(f"เปิด process PID={pid} สำเร็จ, เจอ {len(self.modules)} modules")
        except OSError as e:
            messagebox.showerror("เปิด process ไม่สำเร็จ", str(e))

    # ---------------- Scan ----------------
    def _require_process(self):
        if not self.handle:
            messagebox.showwarning("แจ้งเตือน", "ต้องเปิด process ก่อน")
            return False
        return True

    def _value_type(self):
        return self.type_combo.get() or "int32"

    def _parse_value(self, raw):
        vt = self._value_type()
        return int(raw) if vt in ("int32", "int64") else float(raw)

    def do_first_scan(self):
        if not self._require_process():
            return
        try:
            value = self._parse_value(self.value_entry.get())
        except ValueError:
            messagebox.showerror("ผิดพลาด", "ใส่ค่าตัวเลขให้ถูกต้อง")
            return

        def worker():
            self.log("เริ่ม First Scan ...")
            addrs = first_scan(self.handle, value, self._value_type(), log=self.log)
            self.addresses = addrs
            self.old_values = read_current_values(self.handle, addrs, self._value_type())
            self.log(f"First Scan เสร็จ: เจอ {len(addrs)} address")
            self._refresh_result_list()

        threading.Thread(target=worker, daemon=True).start()

    def do_next_scan(self):
        if not self._require_process():
            return
        if not self.addresses:
            messagebox.showwarning("แจ้งเตือน", "ยังไม่มีผลลัพธ์จาก First Scan")
            return
        mode = self.mode_combo.get()

        def worker():
            if mode == "exact":
                try:
                    value = self._parse_value(self.value_entry.get())
                except ValueError:
                    self.log("ค่าที่ใส่ไม่ถูกต้อง")
                    return
                self.addresses = next_scan(self.handle, self.addresses, self._value_type(), "exact", new_value=value)
            else:
                self.addresses = next_scan(
                    self.handle, self.addresses, self._value_type(), mode, old_values=self.old_values
                )
            self.old_values = read_current_values(self.handle, self.addresses, self._value_type())
            self.log(f"Next Scan ({mode}) เสร็จ: เหลือ {len(self.addresses)} address")
            self._refresh_result_list()

        threading.Thread(target=worker, daemon=True).start()

    def _refresh_result_list(self):
        self.result_list.delete(0, "end")
        for addr in self.addresses[:500]:
            val = self.old_values.get(addr)
            self.result_list.insert("end", f"0x{addr:X} = {val}")
        if len(self.addresses) > 500:
            self.result_list.insert("end", f"... และอีก {len(self.addresses) - 500} address")

    def _get_selected_address(self):
        sel = self.result_list.curselection()
        if not sel:
            return None
        line = self.result_list.get(sel[0])
        if not line.startswith("0x"):
            return None
        return int(line.split(" = ")[0], 16)

    # ---------------- Write ----------------
    def do_write(self):
        if not self._require_process():
            return
        addr = self._get_selected_address()
        if addr is None:
            messagebox.showwarning("แจ้งเตือน", "เลือก address จากรายการผลลัพธ์ก่อน")
            return
        try:
            value = self._parse_value(self.write_entry.get())
        except ValueError:
            messagebox.showerror("ผิดพลาด", "ใส่ค่าตัวเลขให้ถูกต้อง")
            return
        fmt, size = VALUE_TYPES[self._value_type()]
        ok = write_memory(self.handle, addr, struct.pack(fmt, value))
        self.log(f"เขียนค่า 0x{addr:X} = {value}: {'สำเร็จ' if ok else 'ไม่สำเร็จ'}")

    # ---------------- Pointer scan dialog ----------------
    def open_pointer_scan_dialog(self):
        if not self._require_process():
            return
        addr = self._get_selected_address()
        if addr is None:
            messagebox.showwarning("แจ้งเตือน", "เลือก address จากรายการผลลัพธ์ก่อน (นี่คือ target ที่จะหา pointer chain ให้)")
            return

        dlg = tk.Toplevel(self.root)
        dlg.title(f"Pointer Scan สำหรับ 0x{addr:X}")
        dlg.geometry("560x420")

        frm = ttk.Frame(dlg, padding=8)
        frm.pack(fill="x")

        ttk.Label(frm, text="Max level (จำนวนชั้น pointer):").grid(row=0, column=0, sticky="w")
        level_entry = ttk.Entry(frm, width=8)
        level_entry.insert(0, "3")
        level_entry.grid(row=0, column=1, sticky="w")

        ttk.Label(frm, text="Max offset (hex, เช่น 800):").grid(row=1, column=0, sticky="w")
        offset_entry = ttk.Entry(frm, width=8)
        offset_entry.insert(0, "800")
        offset_entry.grid(row=1, column=1, sticky="w")

        ttk.Label(frm, text="Pointer size:").grid(row=2, column=0, sticky="w")
        ptr_size_combo = ttk.Combobox(frm, values=["8 (x64)", "4 (x86)"], width=10, state="readonly")
        ptr_size_combo.set("8 (x64)")
        ptr_size_combo.grid(row=2, column=1, sticky="w")

        result_box = tk.Listbox(dlg, height=15)
        result_box.pack(fill="both", expand=True, padx=8, pady=8)

        def run_scan():
            try:
                max_level = int(level_entry.get())
                max_offset = int(offset_entry.get(), 16)
            except ValueError:
                messagebox.showerror("ผิดพลาด", "ใส่ตัวเลขให้ถูกต้อง")
                return
            pointer_size = 8 if ptr_size_combo.get().startswith("8") else 4
            result_box.delete(0, "end")
            result_box.insert("end", "กำลังสแกน ... (อาจใช้เวลาสักครู่ ขึ้นกับขนาดหน่วยความจำของ process)")

            def worker():
                regions = enumerate_readable_regions(self.handle)
                chains = pointer_scan(
                    self.handle, self.modules, regions, addr,
                    max_level=max_level, max_offset=max_offset,
                    pointer_size=pointer_size, log=self.log,
                )
                self.msg_queue.put(f"Pointer scan เสร็จ: เจอ {len(chains)} chain")

                def update():
                    result_box.delete(0, "end")
                    if not chains:
                        result_box.insert("end", "ไม่เจอ pointer chain ที่เสถียร ลองเพิ่ม max_offset หรือ max_level")
                    for c in chains[:200]:
                        offs = " -> ".join(f"0x{o:X}" for o in c["offsets"])
                        result_box.insert(
                            "end",
                            f'{c["module"]}+0x{c["module_offset"]:X}  =>  offsets: [{offs}]',
                        )
                dlg.after(0, update)

            threading.Thread(target=worker, daemon=True).start()

        ttk.Button(frm, text="เริ่ม Pointer Scan", command=run_scan).grid(row=0, column=2, rowspan=3, padx=12)


def main():
    if not sys.platform.startswith("win"):
        print("โปรแกรมนี้ใช้ WinAPI รันได้บน Windows เท่านั้น")
        sys.exit(1)
    root = tk.Tk()
    MemoryScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

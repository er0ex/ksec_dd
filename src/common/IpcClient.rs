use winapi::{
    shared::{
        minwindef::{BOOL, DWORD, FALSE, LPBYTE, MAX_PATH, PDWORD, TRUE},
        ntdef::{LPWSTR, PHANDLE},
    },
    um::{
        fileapi::{CreateFileW, ReadFile, WriteFile, OPEN_EXISTING}, handleapi::{CloseHandle, INVALID_HANDLE_VALUE}, winnt::{GENERIC_READ, GENERIC_WRITE, WCHAR}
    },
};
use std::{
    ffi::OsStr, os::{raw::c_void, windows::{ffi::OsStrExt, raw::HANDLE}}, ptr::{null, null_mut}
};
use crate::ipc::*;
use crate::commons::*;
use crate::common::nt::*;


pub struct IpcClient{
    m_h_pipe_handle: HANDLE,
    m_pbio_buffer: LPBYTE,
}
impl IpcClient{
    // Конструктор
    pub fn new(&mut self){
        println!("NEW");
        self.m_h_pipe_handle = INVALID_HANDLE_VALUE as _;
        self.m_pbio_buffer = null_mut();
        
        self.m_pbio_buffer =  Common::Alloc(PAGE_SIZE) as LPBYTE;
        if !self.m_h_pipe_handle.is_null() {
            eprintln!("ERROR::ALLOC::MEMORY");
            return ;
        }
        
        return;
    }

    //Деструктор
    pub fn drop(&self) {
        println!("DROP");
        if !self.m_pbio_buffer.is_null() {
            Common::Free(self.m_pbio_buffer as *mut c_void as _);
        }
        if !self.m_h_pipe_handle.is_null() && self.m_h_pipe_handle != INVALID_HANDLE_VALUE as _{
            unsafe{CloseHandle(self.m_h_pipe_handle as _)};
        }
    }

    pub unsafe fn connect_to_name_pipe(&self, pipe_handle: PHANDLE) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let mut pwsz_pipe_name: LPWSTR = null_mut();
        let mut h_pipe = null_mut();


        *pipe_handle = INVALID_HANDLE_VALUE;
        pwsz_pipe_name = Common::Alloc(MAX_PATH * std::mem::size_of::<WCHAR>()) as *mut u16;
        if pwsz_pipe_name.is_null() {
            if !pwsz_pipe_name.is_null() {Common::Free(pwsz_pipe_name as *mut c_void as _);};
            return b_result;
        }
        pwsz_pipe_name = OsStr::new(&format!(r"\\.\pipe\{}", IPC_NAMED_PIPE_NAME)).encode_wide().chain(Some(0)).collect::<Vec<u16>>().as_mut_ptr();

        h_pipe = unsafe{CreateFileW(
            pwsz_pipe_name,
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null_mut(), // SECURITY_ATTRIBUTES* должен быть *mut, а не *const
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(), // HANDLE должен быть *mut, а не *const
        )};

        if h_pipe.is_null() || h_pipe == INVALID_HANDLE_VALUE{
            eprintln!("ERROR::CREATE::FILE");
            if !pwsz_pipe_name.is_null() {Common::Free(pwsz_pipe_name as *mut c_void as _);};
            return b_result;
        }

        *pipe_handle = h_pipe;
        b_result = TRUE;
        return b_result;
    }

    //Соединение
    pub fn connect(&self) -> BOOL{
        println!("CONNECT");
        return unsafe{Self::connect_to_name_pipe(&self, self.m_h_pipe_handle as *mut *mut c_void as _)};
    }

    //Отсоединение
    pub fn disconnect(&mut self) -> BOOL{
        unsafe{
            if CloseHandle(self.m_h_pipe_handle as _) == FALSE{
                eprintln!("ERROR::DISCONNECT::CLOSE_HANDLE");
                return FALSE;
            }
        };

        self.m_h_pipe_handle = INVALID_HANDLE_VALUE as _;
        return FALSE;
    }

    //Проверка соединения
    pub unsafe fn is_connected(&self) -> BOOL {
        return (!self.m_h_pipe_handle.is_null() && self.m_h_pipe_handle != INVALID_HANDLE_VALUE as *mut c_void) as BOOL;
    }

    pub unsafe fn SendAndReceive(&self, io_buffer: LPBYTE, request_size: DWORD, response_size: PDWORD) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let mut dw_bytes_written: DWORD = 0;
        let mut dw_bytes_read: DWORD = 0;

        if unsafe {WriteFile(self.m_h_pipe_handle as _, io_buffer as *const c_void as _, request_size, &mut dw_bytes_written as *mut u32, null_mut()) == FALSE}{
            eprintln!("ERROR::WRITE::FILE");
            return b_result;
        }else {
            b_result = TRUE;
        }

        if unsafe {ReadFile(self.m_h_pipe_handle as _, io_buffer as *const c_void as _, PAGE_SIZE as u32, &mut dw_bytes_read as *mut u32, null_mut()) == FALSE}{
            eprintln!("ERROR::READ::FILE");
            return b_result;
        }else {
            b_result = TRUE;
        }

        return b_result;
    }


    //Пинг запрос
    pub unsafe fn send_ping_request(&self) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let mut req: PIPC_REQUEST_PING = self.m_pbio_buffer as PIPC_REQUEST_PING;
        let resp:  PIPC_RESPONSE_PING = self.m_pbio_buffer as PIPC_RESPONSE_PING;
        let mut dw_responce_size: DWORD = 0;

        (*req).Header.Type = MessageType::Ping as DWORD;
        println!("PING: {:?}", (*req).Message);

        if unsafe{Self::SendAndReceive(self, self.m_pbio_buffer, std::mem::size_of_val(&req) as u32, &mut dw_responce_size as *mut u32) == FALSE}{
            return b_result;
        };


        let message_utf16: &[u16] = &(*resp).Message;
        let message_string = String::from_utf16_lossy(message_utf16);
        if (*resp).Header.Result == FALSE || !message_string.eq_ignore_ascii_case("PONG"){
            eprintln!("ERROR::REQUEST::PING");
            return b_result;
        }else{
            b_result = TRUE;
        }

        return b_result;
    }

    //Отправка остановки серверу
    pub unsafe fn send_stop_server_request(&self) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let req: PIPC_REQUEST_STOP_SERVER = self.m_pbio_buffer as PIPC_REQUEST_STOP_SERVER;
        let resp:  PIPC_RESPONSE_STOP_SERVER = self.m_pbio_buffer as PIPC_RESPONSE_STOP_SERVER;
        let mut dw_responce_size: DWORD = 0;

        (*req).Header.Type = MessageType::StopServer as DWORD;
        if unsafe{Self::SendAndReceive(self, self.m_pbio_buffer, std::mem::size_of_val(&req) as u32, &mut dw_responce_size as *mut u32) == FALSE}{
            return b_result;
        }

        if dw_responce_size != std::mem::size_of_val(&resp) as u32{
            eprintln!("WARNING::RESPONSE::MESSAGE::MISMATCH::{}::SHOULD_BE::{}", dw_responce_size, std::mem::size_of_val(&*resp) as DWORD);
        }
        if (*resp).Header.Result == FALSE{
            eprintln!("ERROR::REQUEST::SERVER");
            return b_result;
        }else{
            b_result = TRUE;
        }
        return b_result;
    }

    //Отправка запроса Query Ci 
    pub unsafe fn send_query_ci_options_request(&self, ci_options: PDWORD) -> BOOL{
        let mut b_result: BOOL = FALSE;
        let mut req: PIPC_REQUEST_QUERY_CI_OPTIONS = self.m_pbio_buffer as PIPC_REQUEST_QUERY_CI_OPTIONS;
        let mut resp: PIPC_RESPONSE_QUERY_CI_OPTIONS = self.m_h_pipe_handle as PIPC_RESPONSE_QUERY_CI_OPTIONS; 
        let mut dw_responce_size: DWORD = 0;

        (*req).Header.Type = MessageType::QueryCiOptions as DWORD;
        if unsafe{Self::SendAndReceive(self, self.m_pbio_buffer, std::mem::size_of_val(&req) as u32, &mut dw_responce_size as *mut u32) == FALSE}{
            return b_result;
        }

        if dw_responce_size != std::mem::size_of_val(&resp) as u32 {
            eprintln!("WARNING::RESPONSE::MESSAGE::MISMATCH::{}::SHOULD_BE::{}", dw_responce_size, std::mem::size_of_val(&resp) as DWORD);
        }
        if (*resp).Header.Result == FALSE {
            eprintln!("ERROR::REQUEST::QUERY_CI");
            return b_result;
        }else {
            b_result = TRUE;
        }

        unsafe{*ci_options = (*resp).CiOptions};
        return b_result;
    }

    //Отправка отключения CI
    pub unsafe fn send_disable_ci_request(&self) -> BOOL{
        let mut b_result: BOOL = FALSE;
        let mut req: PIPC_REQUEST_DISABLE_CI = self.m_pbio_buffer as PIPC_REQUEST_DISABLE_CI;
        let mut resp: PIPC_RESPONSE_DISABLE_CI = self.m_h_pipe_handle as PIPC_RESPONSE_DISABLE_CI; 
        let mut dw_responce_size: DWORD = 0;

        (*req).Header.Type = MessageType::SetCiOptions as DWORD;
        if unsafe{Self::SendAndReceive(self, self.m_pbio_buffer, std::mem::size_of_val(&req) as u32, &mut dw_responce_size as *mut u32) == FALSE}{
            return b_result;
        }

        if dw_responce_size != std::mem::size_of_val(&resp) as u32{
            eprintln!("WARNING::RESPONSE::MESSAGE::MISMATCH::{}::SHOULD_BE::{}", dw_responce_size, std::mem::size_of_val(&resp) as DWORD);
        }
        if (*resp).Header.Result == FALSE{
            eprintln!("ERROR::REQUEST::DISABLE_CI");
            return b_result;
        }else {
            b_result = TRUE;
        }
        return b_result;
    }

    //Установить настройки CI
    pub unsafe fn send_set_ci_options_request(&self, ci_options: DWORD) -> BOOL {
        let mut b_result: BOOL = FALSE;
        let mut req: PIPC_REQUEST_SET_CI_OPTIONS = self.m_pbio_buffer as PIPC_REQUEST_SET_CI_OPTIONS;
        let mut resp: PIPC_RESPONSE_SET_CI_OPTIONS = self.m_h_pipe_handle as PIPC_RESPONSE_SET_CI_OPTIONS; 
        let mut dw_responce_size: DWORD = 0;

        (*req).Header.Type = MessageType::QueryCiOptions as DWORD;
        if unsafe{Self::SendAndReceive(self, self.m_pbio_buffer, std::mem::size_of_val(&req) as u32, &mut dw_responce_size as *mut u32) == FALSE}{
            return b_result;
        } 
        if dw_responce_size != std::mem::size_of_val(&resp) as u32{
            eprintln!("WARNING::RESPONSE::MESSAGE::MISMATCH::{}::SHUOLD_BE::{}", dw_responce_size, std::mem::size_of_val(&resp));
        }
        if (*resp).Header.Result == FALSE{
            eprintln!("ERROR::REQUEST::OPTIONS:CI");
            return b_result;
        }else {
            b_result = TRUE;
        }
        return b_result;
    }

}
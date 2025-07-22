use winapi::shared::{
        minwindef::{BOOL, DWORD},
        ntdef::{WCHAR},
};


pub const IPC_NAMED_PIPE_NAME: &str = "KexecDDPlus";
pub enum MessageType{
    Ping = 1,
    StopServer,
    QueryCiOptions,
    DisableCi,
    SetCiOptions,
    MaxValue,
}

pub struct IPC_REQUEST_HEADER {
    pub Type: DWORD,
}

pub struct IPC_RESPONSE_HEADER {
    pub Type: DWORD,
    pub Result: BOOL,
    pub Status: DWORD,
}

pub struct IPC_REQUEST_PING {
    pub Header: IPC_REQUEST_HEADER,
    pub Message: [WCHAR; 5],
}

pub struct IPC_RESPONSE_PING {
    pub Header: IPC_RESPONSE_HEADER,
    pub Message: [WCHAR; 5],
}

pub struct IPC_REQUEST_STOP_SERVER {
    pub Header: IPC_REQUEST_HEADER,
}

pub struct IPC_RESPONSE_STOP_SERVER {
    pub Header: IPC_RESPONSE_HEADER,
}

pub struct IPC_REQUEST_QUERY_CI_OPTIONS {
    pub Header: IPC_REQUEST_HEADER,
}

pub struct IPC_RESPONSE_QUERY_CI_OPTIONS {
    pub Header: IPC_RESPONSE_HEADER,
    pub CiOptions: DWORD,
}

pub struct IPC_REQUEST_DISABLE_CI {
    pub Header: IPC_REQUEST_HEADER,
}

pub struct IPC_RESPONSE_DISABLE_CI {
    pub Header: IPC_RESPONSE_HEADER,
}

pub struct IPC_REQUEST_SET_CI_OPTIONS {
    pub Header: IPC_REQUEST_HEADER,
    pub CiOptions: DWORD,
}

pub struct IPC_RESPONSE_SET_CI_OPTIONS {
    pub Header: IPC_RESPONSE_HEADER,
}

pub type PIPC_REQUEST_PING = *mut IPC_REQUEST_PING;
pub type PIPC_RESPONSE_PING = *mut IPC_RESPONSE_PING;
pub type PIPC_REQUEST_STOP_SERVER = *mut IPC_REQUEST_STOP_SERVER;
pub type PIPC_RESPONSE_STOP_SERVER = *mut IPC_RESPONSE_STOP_SERVER;
pub type PIPC_REQUEST_QUERY_CI_OPTIONS = *mut IPC_REQUEST_QUERY_CI_OPTIONS;
pub type PIPC_RESPONSE_QUERY_CI_OPTIONS = *mut IPC_RESPONSE_QUERY_CI_OPTIONS;
pub type PIPC_REQUEST_DISABLE_CI = *mut IPC_REQUEST_DISABLE_CI;
pub type PIPC_RESPONSE_DISABLE_CI = *mut IPC_RESPONSE_DISABLE_CI;
pub type PIPC_REQUEST_SET_CI_OPTIONS = *mut IPC_REQUEST_SET_CI_OPTIONS;
pub type PIPC_RESPONSE_SET_CI_OPTIONS = *mut IPC_RESPONSE_SET_CI_OPTIONS;

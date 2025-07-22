use ntapi::{ntioapi::{FILE_INFORMATION_CLASS, PIO_STATUS_BLOCK}, ntpsapi::{PPS_ATTRIBUTE_LIST, PPS_CREATE_INFO}};
use winapi::{ctypes::c_void, shared::{basetsd::{PSIZE_T, SIZE_T, ULONG_PTR}, minwindef::{PULONG, UCHAR, USHORT}, ntdef::{BOOLEAN, HANDLE, NTSTATUS, PHANDLE, PLONG, POBJECT_ATTRIBUTES, PVOID, UNICODE_STRING}, wtypesbase::ULONG}, um::winnt::{ACCESS_MASK, IO_COUNTERS, JOBOBJECTINFOCLASS, JOBOBJECT_BASIC_LIMIT_INFORMATION, PIMAGE_NT_HEADERS, PSECURITY_QUALITY_OF_SERVICE}};

pub const STATUS_SUCCESS: NTSTATUS = 0x00000000;
pub const STATUS_PROCESS_CLONED: NTSTATUS = 0x00000129;

pub const SystemModuleInformation: u32 = 11;
pub const FileIoCompletionNotificationInformation: u32 = 41;
pub const PsAttributeStdHandleInfo: u32 = 10;
pub const PsAttributeJobList: u32 = 19;

pub const PROCESS_CREATE_FLAGS_INHERIT_HANDLES: u32 = 0x00000004;

pub const JobObjectSiloRootDirectory: u32 = 37;
pub const JobObjectServerSiloInitialize: u32 = 40;
pub const JobObjectContainerTelemetryId: u32 = 44;
pub const JobObjectSiloSystemRoot: u32 = 45;

pub const JOB_OBJECT_LIMIT_SILO_READY: u32 = 0x00400000;

pub const SILO_OBJECT_ROOT_DIRECTORY_SHADOW_ROOT: u32 = 0x00000001;
pub const SILO_OBJECT_ROOT_DIRECTORY_INITIALIZE: u32 = 0x00000002;
pub const SILO_OBJECT_ROOT_DIRECTORY_SHADOW_DOS_DEVICES: u32 = 0x00000004;
pub const SILO_OBJECT_ROOT_DIRECTORY_ALL: u32 = SILO_OBJECT_ROOT_DIRECTORY_SHADOW_ROOT | SILO_OBJECT_ROOT_DIRECTORY_INITIALIZE | SILO_OBJECT_ROOT_DIRECTORY_SHADOW_DOS_DEVICES;

pub const PS_ATTRIBUTE_NUMBER_MASK: u32 = 0x0000ffff;
pub const PS_ATTRIBUTE_THREAD: u32 = 0x00010000;
pub const PS_ATTRIBUTE_INPUT: u32 = 0x00020000;
pub const PS_ATTRIBUTE_ADDITIVE: u32 = 0x00040000;

const fn ps_attribute_value(number: u32, thread: bool, input: bool, additive: bool) -> u32 {
    (number & PS_ATTRIBUTE_NUMBER_MASK) |
    (if thread   { PS_ATTRIBUTE_THREAD   } else { 0 }) |
    (if input    { PS_ATTRIBUTE_INPUT    } else { 0 }) |
    (if additive { PS_ATTRIBUTE_ADDITIVE } else { 0 })
}

const PS_ATTRIBUTE_JOB_LIST: u32 = ps_attribute_value(PsAttributeJobList, false, true, false);


pub struct RTL_PROCESS_MODULE_INFORMATION{
    Section: HANDLE,
    MappedBase: PVOID,
    ImageBase: PVOID,
    ImageSize: ULONG,
    Flags: ULONG,
    LoadOrderIndex: USHORT,
    InitOrderIndex: USHORT,
    LoadCount: USHORT,
    OffsetToFileName: USHORT,
    FullPathName: [UCHAR; 256],
}


pub struct RTL_PROCESS_MODULE{
    NumberOfModules: ULONG,
    Modules: [RTL_PROCESS_MODULE_INFORMATION; 1],
}
#[repr(C)]
union ValueUnion {
    Value: usize,
    ValuePtr: *mut c_void,
}
pub struct PS_ATTRIBUTE{
    Attribute: ULONG_PTR,
    Size: SIZE_T,
    value_union: ValueUnion,
    ReturnLenght: PSIZE_T,
}

pub struct PS_ATTRIBUTE_LIST {
    TotalLenght: SIZE_T,
    Attributes: [PS_ATTRIBUTE; 1],
}

/*
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FlagsStruct {
    pub StdHandleState: ULONG,
}

#[repr(C)]
pub union FlagsUnion {
    pub Flags: u32,
    pub s: FlagsStruct,
}

#[repr(C)]
pub struct PS_STD_HANDLE_INFO {
    pub u: FlagsUnion,
    pub StdHandleSubsystemType: u32,
}
*/




enum PS_STD_HANDLE_STATE {
    PsNeverDuplicate,
    PsRequestDuplicate,
    PsAlwaysDuplicate, 
    PsMaxStdHandleStates
}

enum PS_CREATE_STATE {
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName,
    PsCreateSuccess,
    PsCreateMaximumStates
}
/*
struct PS_CREATE_INFO{

}
*/




pub const FILE_SKIP_COMPLETION_PORT_ON_SUCCESS: u32 = 0x1;
pub const FILE_SKIP_SET_EVENT_ON_HANDLE: u32 = 0x2;
pub const FILE_SKIP_SET_USER_EVENT_ON_FAST_IO: u32 = 0x4;


pub struct FILE_IO_COMPLETION_NOTIFICATION_INFORMATION {
    pub Flags: ULONG,
}


#[repr(C)]
pub union silobj {
    pub ControlFlags: ULONG,
    pub Path: UNICODE_STRING,
}
pub struct SILOOBJECT_ROOT_DIRECTORY {
    pub sil_obj: silobj,
}


pub struct SERVERSILO_INIT_INFORMATION {
    pub DelereEvent: HANDLE,
    pub IsDownLevelContainer: BOOLEAN,
}

pub struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION_V2 {
    pub BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
    pub IoInfo: IO_COUNTERS,
    pub ProcessMemoryLimit: SIZE_T,
    pub JobMemoryLimit: SIZE_T,
    pub PeakProcessMemoryUsed: SIZE_T,
    pub PeakJobMemoryUsed: SIZE_T,
    pub JobTotalMemoryLimit: SIZE_T,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    #[must_use]
    pub unsafe fn RtlCreateUnicodeString(
        DestinationString:  UNICODE_STRING,
        SourceString: *const u16,
    ) -> u8; // BOOLEAN = u8
}

#[link(name = "ntdll")]
unsafe extern "system" {
    pub unsafe fn RtlImageNtHeader(
        ModuleAddress: PVOID
    ) -> PIMAGE_NT_HEADERS;
}

#[link(name = "ntdll")]
unsafe extern "system" {
    pub unsafe fn NtCreateUserProcess(
        ProcessHandle: PHANDLE,
        ThreadHandle: PHANDLE,
        ProcessDesiredAccess: ACCESS_MASK,
        ThreadDesiredAccess: ACCESS_MASK,
        ProcessObjectAttributes: POBJECT_ATTRIBUTES,
        ThreadObjectAttributes: POBJECT_ATTRIBUTES,
        ProcessFlags: ULONG,
        ThreadFlags: ULONG,
        ProcessParameters: PVOID,
        CreateInfo: PPS_CREATE_INFO,
        AttributeList: PPS_ATTRIBUTE_LIST,
    ) -> NTSTATUS;
}

#[link(name = "ntdll")]
unsafe extern "system" {
    #[must_use]
    pub unsafe fn NtTerminateProcess(
        ProcessHandle: HANDLE,
        ExitStatus: NTSTATUS,
    ) -> NTSTATUS;

    #[must_use]
    pub unsafe fn NtImpersonateThread(
        ServerThreadHandle: HANDLE,
        ClientThreadHandle: HANDLE,
        SecurityQos: PSECURITY_QUALITY_OF_SERVICE,
    ) -> NTSTATUS;

    #[must_use]
    pub unsafe fn NtOpenEvent(
        EventHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;

    #[must_use]
    pub unsafe fn NtSetEvent(
        EventHandle: HANDLE,
        PreviousState: PLONG,
    ) -> NTSTATUS;

    #[must_use]
    pub unsafe fn NtOpenDirectoryObject(
        DirectoryHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;

    #[must_use]
    pub unsafe fn NtCreateDirectoryObjectEx(
        DirectoryHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        ShadowDirectoryHandle: HANDLE,
        Flags: ULONG,
    ) -> NTSTATUS;

    #[must_use]
    pub unsafe fn NtSetInformationFile(
        FileHandle: HANDLE,
        IoStatusBlock: PIO_STATUS_BLOCK,
        FileInformation: PVOID,
        Length: ULONG,
        FileInformationClass: FILE_INFORMATION_CLASS,
    ) -> NTSTATUS;

    #[must_use]
    pub unsafe fn NtCreateJobObject(
        JobHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;

    #[must_use]
    pub unsafe fn NtSetInformationJobObject(
        JobHandle: HANDLE,
        JobObjectInformationClass: JOBOBJECTINFOCLASS,
        JobObjectInformation: PVOID,
        JobObjectInformationLength: ULONG,
    ) -> NTSTATUS;

    #[must_use]
    pub unsafe fn NtQueryInformationJobObject(
        JobHandle: HANDLE,
        JobObjectInformationClass: JOBOBJECTINFOCLASS,
        JobObjectInformation: PVOID,
        JobObjectInforULONGLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;

    #[must_use]
    pub unsafe fn NtTerminateJobObject(
        JobHandle: HANDLE,
        ExitStatus: NTSTATUS,
    ) -> NTSTATUS;

    #[must_use]
    pub unsafe fn NtAssignProcessToJobObject(
        JobHandle: HANDLE,
        ProcessHandle: HANDLE,
    ) -> NTSTATUS;
}

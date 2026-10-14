windows_link::link!("advapi32.dll" "system" fn AddAccessAllowedAceEx(pacl : *mut ACL, dwacerevision : u32, aceflags : u32, accessmask : u32, psid : PSID) -> BOOL);
windows_link::link!("advapi32.dll" "system" fn CopySid(ndestinationsidlength : u32, pdestinationsid : PSID, psourcesid : PSID) -> BOOL);
windows_link::link!("advapi32.dll" "system" fn CreateWellKnownSid(wellknownsidtype : WELL_KNOWN_SID_TYPE, domainsid : PSID, psid : PSID, cbsid : *mut u32) -> BOOL);
windows_link::link!("kernel32.dll" "system" fn DeviceIoControl(hdevice : HANDLE, dwiocontrolcode : u32, lpinbuffer : *const core::ffi::c_void, ninbuffersize : u32, lpoutbuffer : *mut core::ffi::c_void, noutbuffersize : u32, lpbytesreturned : *mut u32, lpoverlapped : *mut OVERLAPPED) -> BOOL);
windows_link::link!("advapi32.dll" "system" fn EqualSid(psid1 : PSID, psid2 : PSID) -> BOOL);
windows_link::link!("kernel32.dll" "system" fn FlushFileBuffers(hfile : HANDLE) -> BOOL);
windows_link::link!("advapi32.dll" "system" fn GetAce(pacl : *const ACL, dwaceindex : u32, pace : *mut *mut core::ffi::c_void) -> BOOL);
windows_link::link!("kernel32.dll" "system" fn GetCurrentProcess() -> HANDLE);
windows_link::link!("kernel32.dll" "system" fn GetFileInformationByHandleEx(hfile : HANDLE, fileinformationclass : FILE_INFO_BY_HANDLE_CLASS, lpfileinformation : *mut core::ffi::c_void, dwbuffersize : u32) -> BOOL);
windows_link::link!("kernel32.dll" "system" fn GetFileType(hfile : HANDLE) -> u32);
windows_link::link!("kernel32.dll" "system" fn GetHandleInformation(hobject : HANDLE, lpdwflags : *mut u32) -> BOOL);
windows_link::link!("advapi32.dll" "system" fn GetLengthSid(psid : PSID) -> u32);
windows_link::link!("advapi32.dll" "system" fn GetSecurityDescriptorControl(psecuritydescriptor : PSECURITY_DESCRIPTOR, pcontrol : *mut u16, lpdwrevision : *mut u32) -> BOOL);
windows_link::link!("advapi32.dll" "system" fn GetSecurityInfo(handle : HANDLE, objecttype : SE_OBJECT_TYPE, securityinfo : SECURITY_INFORMATION, ppsidowner : *mut PSID, ppsidgroup : *mut PSID, ppdacl : *mut PACL, ppsacl : *mut PACL, ppsecuritydescriptor : *mut PSECURITY_DESCRIPTOR) -> u32);
windows_link::link!("advapi32.dll" "system" fn GetTokenInformation(tokenhandle : HANDLE, tokeninformationclass : TOKEN_INFORMATION_CLASS, tokeninformation : *mut core::ffi::c_void, tokeninformationlength : u32, returnlength : *mut u32) -> BOOL);
windows_link::link!("kernel32.dll" "system" fn GetVolumeInformationByHandleW(hfile : HANDLE, lpvolumenamebuffer : PWSTR, nvolumenamesize : u32, lpvolumeserialnumber : *mut u32, lpmaximumcomponentlength : *mut u32, lpfilesystemflags : *mut u32, lpfilesystemnamebuffer : PWSTR, nfilesystemnamesize : u32) -> BOOL);
windows_link::link!("advapi32.dll" "system" fn InitializeAcl(pacl : *mut ACL, nacllength : u32, dwaclrevision : u32) -> BOOL);
windows_link::link!("advapi32.dll" "system" fn InitializeSecurityDescriptor(psecuritydescriptor : PSECURITY_DESCRIPTOR, dwrevision : u32) -> BOOL);
windows_link::link!("advapi32.dll" "system" fn IsValidAcl(pacl : *const ACL) -> BOOL);
windows_link::link!("advapi32.dll" "system" fn IsValidSid(psid : PSID) -> BOOL);
windows_link::link!("kernel32.dll" "system" fn LocalFree(hmem : HLOCAL) -> HLOCAL);
windows_link::link!("ntdll.dll" "system" fn NtCreateFile(filehandle : *mut HANDLE, desiredaccess : ACCESS_MASK, objectattributes : *const OBJECT_ATTRIBUTES, iostatusblock : *mut IO_STATUS_BLOCK, allocationsize : *const i64, fileattributes : u32, shareaccess : u32, createdisposition : u32, createoptions : u32, eabuffer : *const core::ffi::c_void, ealength : u32) -> NTSTATUS);
windows_link::link!("ntdll.dll" "system" fn NtSetInformationFile(filehandle : HANDLE, iostatusblock : *mut IO_STATUS_BLOCK, fileinformation : *const core::ffi::c_void, length : u32, fileinformationclass : FILE_INFORMATION_CLASS) -> NTSTATUS);
windows_link::link!("advapi32.dll" "system" fn OpenProcessToken(processhandle : HANDLE, desiredaccess : u32, tokenhandle : *mut HANDLE) -> BOOL);
windows_link::link!("ntdll.dll" "system" fn RtlNtStatusToDosError(status : NTSTATUS) -> u32);
windows_link::link!("kernel32.dll" "system" fn SetFileInformationByHandle(hfile : HANDLE, fileinformationclass : FILE_INFO_BY_HANDLE_CLASS, lpfileinformation : *const core::ffi::c_void, dwbuffersize : u32) -> BOOL);
windows_link::link!("advapi32.dll" "system" fn SetSecurityDescriptorControl(psecuritydescriptor : PSECURITY_DESCRIPTOR, controlbitsofinterest : SECURITY_DESCRIPTOR_CONTROL, controlbitstoset : SECURITY_DESCRIPTOR_CONTROL) -> BOOL);
windows_link::link!("advapi32.dll" "system" fn SetSecurityDescriptorDacl(psecuritydescriptor : PSECURITY_DESCRIPTOR, bdaclpresent : BOOL, pdacl : *const ACL, bdacldefaulted : BOOL) -> BOOL);
windows_link::link!("advapi32.dll" "system" fn SetSecurityDescriptorOwner(psecuritydescriptor : PSECURITY_DESCRIPTOR, powner : PSID, bownerdefaulted : BOOL) -> BOOL);
windows_link::link!("advapi32.dll" "system" fn SetSecurityInfo(handle : HANDLE, objecttype : SE_OBJECT_TYPE, securityinfo : SECURITY_INFORMATION, psidowner : PSID, psidgroup : PSID, pdacl : *const ACL, psacl : *const ACL) -> u32);
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ACCESS_ALLOWED_ACE {
    pub Header: ACE_HEADER,
    pub Mask: ACCESS_MASK,
    pub SidStart: u32,
}
pub const ACCESS_ALLOWED_ACE_TYPE: i32 = 0;
pub type ACCESS_MASK = u32;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ACE_HEADER {
    pub AceType: u8,
    pub AceFlags: u8,
    pub AceSize: u16,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ACL {
    pub AclRevision: u8,
    pub Sbz1: u8,
    pub AclSize: u16,
    pub AceCount: u16,
    pub Sbz2: u16,
}
pub const ACL_REVISION: i32 = 2;
pub type BOOL = i32;
pub type CCHAR = i8;
pub const CONTAINER_INHERIT_ACE: i32 = 2;
pub const DACL_SECURITY_INFORMATION: i32 = 4;
pub const DELETE: i32 = 65536;
pub const ERROR_INSUFFICIENT_BUFFER: i32 = 122;
pub const ERROR_NO_MORE_FILES: i32 = 18;
pub const FILE_ALL_ACCESS: i32 = 2032127;
pub const FILE_ATTRIBUTE_DIRECTORY: i32 = 16;
pub const FILE_ATTRIBUTE_NORMAL: i32 = 128;
pub const FILE_ATTRIBUTE_REPARSE_POINT: i32 = 1024;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FILE_ATTRIBUTE_TAG_INFO {
    pub FileAttributes: u32,
    pub ReparseTag: u32,
}
pub const FILE_CREATE: i32 = 2;
pub const FILE_DIRECTORY_FILE: i32 = 1;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FILE_DISPOSITION_INFO {
    pub DeleteFile: bool,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FILE_ID_128 {
    pub Identifier: [u8; 16],
}
impl Default for FILE_ID_128 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FILE_ID_BOTH_DIR_INFO {
    pub NextEntryOffset: u32,
    pub FileIndex: u32,
    pub CreationTime: i64,
    pub LastAccessTime: i64,
    pub LastWriteTime: i64,
    pub ChangeTime: i64,
    pub EndOfFile: i64,
    pub AllocationSize: i64,
    pub FileAttributes: u32,
    pub FileNameLength: u32,
    pub EaSize: u32,
    pub ShortNameLength: CCHAR,
    pub ShortName: [u16; 12],
    pub FileId: i64,
    pub FileName: [u16; 1],
}
impl Default for FILE_ID_BOTH_DIR_INFO {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FILE_ID_INFO {
    pub VolumeSerialNumber: u64,
    pub FileId: FILE_ID_128,
}
pub type FILE_INFORMATION_CLASS = i32;
pub type FILE_INFO_BY_HANDLE_CLASS = i32;
pub const FILE_LIST_DIRECTORY: i32 = 1;
pub const FILE_NON_DIRECTORY_FILE: i32 = 64;
pub const FILE_OPEN: i32 = 1;
pub const FILE_OPEN_IF: i32 = 3;
pub const FILE_OPEN_REPARSE_POINT: i32 = 2097152;
pub const FILE_PERSISTENT_ACLS: i32 = 8;
pub const FILE_READ_ATTRIBUTES: i32 = 128;
pub const FILE_READ_DATA: i32 = 1;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FILE_RENAME_INFORMATION {
    pub Anonymous: FILE_RENAME_INFORMATION_0,
    pub RootDirectory: HANDLE,
    pub FileNameLength: u32,
    pub FileName: [u16; 1],
}
impl Default for FILE_RENAME_INFORMATION {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union FILE_RENAME_INFORMATION_0 {
    pub ReplaceIfExists: bool,
    pub Flags: u32,
}
impl Default for FILE_RENAME_INFORMATION_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub const FILE_RENAME_POSIX_SEMANTICS: i32 = 2;
pub const FILE_RENAME_REPLACE_IF_EXISTS: i32 = 1;
pub const FILE_SHARE_DELETE: i32 = 4;
pub const FILE_SHARE_READ: i32 = 1;
pub const FILE_SHARE_WRITE: i32 = 2;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FILE_STANDARD_INFO {
    pub AllocationSize: i64,
    pub EndOfFile: i64,
    pub NumberOfLinks: u32,
    pub DeletePending: bool,
    pub Directory: bool,
}
pub const FILE_SYNCHRONOUS_IO_NONALERT: i32 = 32;
pub const FILE_TYPE_DISK: i32 = 1;
pub const FILE_WRITE_DATA: i32 = 2;
pub const FSCTL_SET_REPARSE_POINT: i32 = 589988;
pub const FileAttributeTagInfo: FILE_INFO_BY_HANDLE_CLASS = 9;
pub const FileDispositionInfo: FILE_INFO_BY_HANDLE_CLASS = 4;
pub const FileIdBothDirectoryInfo: FILE_INFO_BY_HANDLE_CLASS = 10;
pub const FileIdBothDirectoryRestartInfo: FILE_INFO_BY_HANDLE_CLASS = 11;
pub const FileIdInfo: FILE_INFO_BY_HANDLE_CLASS = 18;
pub const FileRenameInformation: FILE_INFORMATION_CLASS = 10;
pub const FileRenameInformationEx: FILE_INFORMATION_CLASS = 65;
pub const FileStandardInfo: FILE_INFO_BY_HANDLE_CLASS = 1;
pub type HANDLE = *mut core::ffi::c_void;
pub const HANDLE_FLAG_INHERIT: i32 = 1;
pub type HLOCAL = HANDLE;
pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 2684354563;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IO_STATUS_BLOCK {
    pub Anonymous: IO_STATUS_BLOCK_0,
    pub Information: usize,
}
impl Default for IO_STATUS_BLOCK {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union IO_STATUS_BLOCK_0 {
    pub Status: NTSTATUS,
    pub Pointer: *mut core::ffi::c_void,
}
impl Default for IO_STATUS_BLOCK_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub type NTSTATUS = i32;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: HANDLE,
    pub ObjectName: PUNICODE_STRING,
    pub Attributes: u32,
    pub SecurityDescriptor: *mut core::ffi::c_void,
    pub SecurityQualityOfService: *mut core::ffi::c_void,
}
pub const OBJECT_INHERIT_ACE: i32 = 1;
pub const OBJ_CASE_INSENSITIVE: i32 = 64;
pub const OBJ_DONT_REPARSE: i32 = 4096;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OVERLAPPED {
    pub Internal: usize,
    pub InternalHigh: usize,
    pub Anonymous: OVERLAPPED_0,
    pub hEvent: HANDLE,
}
impl Default for OVERLAPPED {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union OVERLAPPED_0 {
    pub Anonymous: OVERLAPPED_0_0,
    pub Pointer: *mut core::ffi::c_void,
}
impl Default for OVERLAPPED_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct OVERLAPPED_0_0 {
    pub Offset: u32,
    pub OffsetHigh: u32,
}
pub const OWNER_SECURITY_INFORMATION: i32 = 1;
pub type PACL = *mut ACL;
pub const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 2147483648;
pub type PSECURITY_DESCRIPTOR = *mut core::ffi::c_void;
pub type PSID = *mut core::ffi::c_void;
pub type PUNICODE_STRING = *mut UNICODE_STRING;
pub type PWSTR = *mut u16;
pub const READ_CONTROL: i32 = 131072;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SECURITY_DESCRIPTOR {
    pub Revision: u8,
    pub Sbz1: u8,
    pub Control: SECURITY_DESCRIPTOR_CONTROL,
    pub Owner: PSID,
    pub Group: PSID,
    pub Sacl: PACL,
    pub Dacl: PACL,
}
pub type SECURITY_DESCRIPTOR_CONTROL = u16;
pub const SECURITY_DESCRIPTOR_REVISION: i32 = 1;
pub type SECURITY_INFORMATION = u32;
pub const SE_DACL_PRESENT: i32 = 4;
pub const SE_DACL_PROTECTED: i32 = 4096;
pub const SE_FILE_OBJECT: SE_OBJECT_TYPE = 1;
pub type SE_OBJECT_TYPE = i32;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SID_AND_ATTRIBUTES {
    pub Sid: PSID,
    pub Attributes: u32,
}
pub const STATUS_INVALID_INFO_CLASS: NTSTATUS = 0xC0000003_u32 as _;
pub const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000000D_u32 as _;
pub const STATUS_NOT_SUPPORTED: NTSTATUS = 0xC00000BB_u32 as _;
pub const STATUS_REPARSE_POINT_ENCOUNTERED: NTSTATUS = 0xC000050B_u32 as _;
pub const STATUS_STOPPED_ON_SYMLINK: NTSTATUS = 0x8000002D_u32 as _;
pub const SYNCHRONIZE: i32 = 1048576;
pub type TOKEN_INFORMATION_CLASS = i32;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TOKEN_OWNER {
    pub Owner: PSID,
}
pub const TOKEN_QUERY: i32 = 8;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TOKEN_USER {
    pub User: SID_AND_ATTRIBUTES,
}
pub const TokenOwner: TOKEN_INFORMATION_CLASS = 4;
pub const TokenUser: TOKEN_INFORMATION_CLASS = 1;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: PWSTR,
}
pub const UNPROTECTED_DACL_SECURITY_INFORMATION: i32 = 536870912;
pub type WELL_KNOWN_SID_TYPE = i32;
pub const WRITE_DAC: i32 = 262144;
pub const WinWorldSid: WELL_KNOWN_SID_TYPE = 1;

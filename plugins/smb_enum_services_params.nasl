#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(44401);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2016/10/20 18:57:23 $");
 
 script_name(english:"Microsoft Windows SMB Service Config Enumeration");
 script_summary(english:"Enumerates the list of remote services.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to enumerate configuration parameters of remote
services.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to obtain, via the SMB protocol, the launch parameters
of each active service on the remote host (executable path, logon
type, etc).");
 script_set_attribute(attribute:"solution", value:"Ensure that each service is configured properly.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/05");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_enum_services.nasl");
 script_exclude_keys("SMB/not_windows");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/svcs");
 script_require_ports(139, 445);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

OPNUM_QUERYSERVICECONFIGA = 0x1d;
OPNUM_QUERYSERVICECONFIGW = 0x11;

global_var hklm, programfilesdir, programfilesdirx86, systemroot;

#
# QueryServiceConfig()
#   handle: Handle to a given service
#
# Returns:
#   ret[0] = service_type
#   ret[1] = start_type
#   ret[2] = error_control
#   ret[3] = tag_id
#   ret[4] = executablepath
#   ret[5] = loadordergroup
#   ret[6] = dependencies
#   ret[7] = startname
#   ret[8] = displayname
#
function QueryServiceConfig(handle)
{
 local_var data, opnum, rep, resp, ret, length, pos, i, len, offset, sub;

 if (session_is_unicode() == 1)
   opnum = OPNUM_QUERYSERVICECONFIGW;
 else
   opnum = OPNUM_QUERYSERVICECONFIGA;


 data = handle[0]                     +  # Handle
        raw_dword (d:0);                 # Buffer size = 0

 data = dce_rpc_pipe_request (fid:handle[1], code:opnum, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 10))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if ( resp != ERROR_MORE_DATA && resp != ERROR_INSUFFICIENT_BUFFER )
   return NULL;

 length = get_dword (blob:rep, pos:36);

 data = handle[0]                     +  # Handle
        raw_dword (d:length);            # Buffer size

 data = dce_rpc_pipe_request (fid:handle[1], code:opnum, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 4))
   return NULL;

 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;


#  typedef [public,gensize] struct {
#                uint32 service_type;
#                svcctl_StartType start_type;
#                svcctl_ErrorControl error_control;
#                [string,charset(UTF16)] [range(0,8192)] uint16 *executablepath;
#               [string,charset(UTF16)] [range(0,8192)] uint16 *loadordergroup;
#                uint32 tag_id;
#                [string,charset(UTF16)] [range(0,8192)] uint16 *dependencies;
#                [string,charset(UTF16)] [range(0,8192)] uint16 *startname;
#                [string,charset(UTF16)] [range(0,8192)] uint16 *displayname;
#        } QUERY_SERVICE_CONFIG;


 ret = make_list();
 ret[0] = get_dword(blob:rep, pos:0);   # service_type
 ret[1] = get_dword(blob:rep, pos:4);   # start_type
 ret[2] = get_dword(blob:rep, pos:8);   # error_control

 # skip the pointers
 pos = 20;
 ret[3] = get_dword(blob:rep, pos:pos); # tag_id

 # skip the remaining pointers
 pos += 16;


 # Now, parse the pointers

 # [string,charset(UTF16)] [range(0,8192)] uint16 * executablepath
 # [string,charset(UTF16)] [range(0,8192)] uint16 *loadordergroup;
 # [string,charset(UTF16)] [range(0,8192)] uint16 * dependencies;
 # [string,charset(UTF16)] [range(0,8192)] uint16 * startName;
 # [string,charset(UTF16)] [range(0,8192)] uint16 * displayname;

 for ( i = 0 ; i < 5 ; i ++ )
 {
  len = get_dword(blob:rep, pos:pos);
  offset = get_dword(blob:rep, pos:pos+4);
  pos += 12;
  if ( session_is_unicode() ) len *= 2;
  sub = substr(rep, pos, pos + len);
  ret[4+i] = get_string(blob:sub, pos:0);
  pos += len + len%4;
 }

 if ( ret[6] == "/" ) ret[6] = "";

 return ret;
}

#
# regQueryServiceConfig()
#   handle: Handle to a given service
#
# Returns:
#   ret[0] = service_type
#   ret[1] = start_type
#   ret[2] = error_control
#   ret[3] = tag_id
#   ret[4] = executablepath
#   ret[5] = loadordergroup
#   ret[6] = dependencies
#   ret[7] = startname
#   ret[8] = displayname
#
function regQueryServiceConfig(handle, svc)
{
  if(isnull(handle) || empty_or_null(svc))
    return NULL;

  local_var key, key_h, pattern, tmp, value;
  local_var ret = make_list();

  key = "SYSTEM\CurrentControlSet\Services\" + svc;
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if(isnull(key_h))
    return NULL;

  value = RegQueryValue(handle:key_h, item:"Type");
  if (!empty_or_null(value)) ret[0] = value[1];
  else ret[0] = NULL;

  value = RegQueryValue(handle:key_h, item:"Start");
  if (!empty_or_null(value)) ret[1] = value[1];
  else ret[1] = NULL;

  value = RegQueryValue(handle:key_h, item:"ErrorControl");
  if (!empty_or_null(value)) ret[2] = value[1];
  else ret[2] = NULL;

  value = RegQueryValue(handle:key_h, item:"Tag");
  if (!empty_or_null(value)) ret[3] = value[1];
  else ret[3] = 0; # For consistency with QueryServiceConfig()

  value = RegQueryValue(handle:key_h, item:"ImagePath");
  if (!empty_or_null(value))
  {
    pattern = '(%systemroot%|%windir%)';
    ret[4]  = ereg_replace(string:value[1],
                           pattern:pattern,
                           replace:systemroot,
                           icase:true);

    pattern = '%programfiles%';
    ret[4]  = ereg_replace(string:ret[4],
                           pattern:pattern,
                           replace:programfilesdir,
                           icase:true);

    pattern = '%programfiles\\(x86\\)%';
    ret[4]  = ereg_replace(string:ret[4],
                           pattern:pattern,
                           replace:programfilesdirx86,
                           icase:true);
  }
  else ret[4] = NULL;

  value = RegQueryValue(handle:key_h, item:"Group");
  if (!empty_or_null(value)) ret[5] = value[1];
  else ret[5] = NULL;

  value = RegQueryValue(handle:key_h, item:"DependOnService");
  if (!empty_or_null(value))
  {
    ret[6] = chomp(value[1]);
    ret[6] = str_replace(string:ret[6], find:'\x00', replace:'/') + '/';
  }
  else ret[6] = ""; # For consistency with QueryServiceConfig()

  value = RegQueryValue(handle:key_h, item:"DependOnGroup");
  if (!empty_or_null(value))
  {
    tmp = chomp(value[1]);
    tmp = '+' + str_replace(string:tmp, find:'\x00', replace:'/+') + '/';
    ret[6] += tmp;
  }

  value = RegQueryValue(handle:key_h, item:"ObjectName");
  if (!empty_or_null(value)) ret[7] = value[1];
  else ret[7] = NULL;

  ret[8] = get_kb_item("SMB/svc/" + svc + "/display_name");

  RegCloseKey(handle:key_h);
  return ret;
}

#
# initRegistryChecks()
#
# Opens a handle to HKLM and gathers environmental variables needed
# to expand service image paths obtained from the registry
#
function initRegistryChecks()
{
  local_var key, key_h, value;

  hklm  = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
  if (isnull(hklm))
  {
    NetUseDel();
    audit(AUDIT_REG_FAIL);
  }

  systemroot = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/SystemRoot");
  if(!systemroot)
  {
    key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

    if(!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"SystemRoot");
      RegCloseKey(handle:key_h);

      if(!isnull(value))
      {
        set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/SystemRoot", value:value[1]);
        systemroot = value[1];
      }
    }
  }

  programfilesdir = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/ProgramFilesDir");
  if(!programfilesdir)
  {
    key = "SOFTWARE\Microsoft\Windows\CurrentVersion";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

    if(!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"ProgramFilesDir");
      RegCloseKey(handle:key_h);

      if(!isnull(value))
      {
        set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/ProgramFilesDir", value:value[1]);
        programfilesdir = value[1];
      }
    }
  }

  programfilesdirx86 = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/ProgramFilesDirx86");
  if(!programfilesdirx86)
  {
    key = "SOFTWARE\Microsoft\Windows\CurrentVersion";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

    if(!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"ProgramFilesDir (x86)");
      RegCloseKey(handle:key_h);

      if(!isnull(value))
      {
        set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/ProgramFilesDirx86", value:value[1]);
        programfilesdirx86 = value[1];
      }
    }
  }
}

### Main

svc_list = get_kb_list_or_exit("SMB/svc/*");

port = kb_smb_transport();
if(!port) port = 445;

login = kb_smb_login();
pass  = kb_smb_password();
dom   = kb_smb_domain();

if(!login) login = "";
if(!pass)  pass  = "";

if(! smb_session_init())
  audit(AUDIT_FN_FAIL, "smb_session_init");

ret = NetUseAdd (login:login, password:pass, domain:dom, share:"IPC$");
if (ret != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, 'IPC$', code:0);
}

if (get_kb_item("nessus/product/agent"))
{
  agent = TRUE;
  initRegistryChecks();
}

else
{
  agent = FALSE;

  handle = OpenSCManager (access_mode:SC_MANAGER_ENUMERATE_SERVICE);
  if (isnull (handle))
  {
    NetUseDel();
    audit(AUDIT_FN_FAIL, "OpenSCManager");
  }
}

auto     = make_list();
manual   = make_list();
disabled = make_list();

foreach svc ( sort(keys(svc_list)) )
{
  if ( !ereg(string:svc, pattern:'^SMB/svc/[^/]+$') ) continue;
  svc -= "SMB/svc/";

  if(agent)
    res = regQueryServiceConfig(handle:hklm, svc:svc);
  else
  {
    ret = OpenService(service:svc, handle:handle, access_mode:SERVICE_ALL_ACCESS);
    res = QueryServiceConfig(handle:ret);
  }

  if ( ! isnull(res) )
  {
    info = '';
    info += '  ' + svc + ' startup parameters :\n';
    if ( res[8] ) info += '    Display name : ' + res[8] + '\n';
    info += '    Service name : ' + svc + '\n';
    if ( res[7] ) info += '    Log on as : ' + res[7] + '\n';
    if ( res[4] )
    {
      set_kb_item(name:'SMB/svc/'+svc+'/path', value:res[4]);
      info += '    Executable path : ' + res[4] + '\n';
    }
    if ( res[6] ) info += '    Dependencies : ' + res[6] + '\n';

    if ( res[1] )
    {
      set_kb_item(name:'SMB/svc/'+svc+'/startuptype', value:res[1]);
      if ( res[1] == SERVICE_AUTO_START ) auto = make_list(auto, info);
      else if ( res[1] == SERVICE_DEMAND_START ) manual = make_list(manual, info);
      else if ( res[1] == SERVICE_DISABLED ) disabled = make_list(disabled, info);
    }
  }
  if(!agent)
    CloseServiceHandle(handle:ret);
}

if(agent)
  RegCloseKey(handle:hklm);
else
  CloseServiceHandle(handle:handle);

NetUseDel();

report = NULL;
if (max_index(auto) > 0)
{
  report += '\nThe following services are set to start automatically :\n\n';
  report += join(auto, sep:'\n');
}
if (max_index(manual) > 0)
{
  report += '\nThe following services must be started manually :\n\n';
  report += join(manual, sep:'\n');
}
if (max_index(disabled) > 0)
{
  report += '\nThe following services are disabled :\n\n';
  report += join(disabled, sep:'\n');
}

if ( strlen(report) )
  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);

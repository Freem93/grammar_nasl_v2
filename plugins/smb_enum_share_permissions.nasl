#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60119);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/27 20:56:56 $");

  script_name(english:"Microsoft Windows SMB Share Permissions Enumeration");
  script_summary(english:"Enumerates network share permissions.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to enumerate the permissions of remote network shares.");
  script_set_attribute(attribute:"description", value:
"By using the supplied credentials, Nessus was able to enumerate the
permissions of network shares. User permissions are enumerated for
each network share that has a list of access control entries (ACEs).");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/bb456988.aspx");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/cc783530.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
  script_require_keys("SMB/transport", "SMB/name");
  script_require_ports(139, 445);

  exit(0);
}

include("misc_func.inc");
include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");
#include("functional.inc");
include("obj.inc");

global_var perm_array, perm_pad_size;
perm_array = make_array(
 ACCESS_READ,    "ACCESS_READ",
 ACCESS_WRITE,   "ACCESS_WRITE",
 ACCESS_CREATE,  "ACCESS_CREATE",
 ACCESS_EXEC,    "ACCESS_EXEC",
 ACCESS_DELETE,  "ACCESS_DELETE",
 ACCESS_ATRIB,   "ACCESS_ATRIB",
 ACCESS_PERM,    "ACCESS_PERM",
 ACCESS_GROUP,   "ACCESS_GROUP",
 ACCESS_ALL,     "ACCESS_ALL",
 DELETE,         "DELETE",
 READ_CONTROL,   "READ_CONTROL",
 WRITE_DAC,      "WRITE_DAC",
 WRITE_OWNER,    "WRITE_OWNER",
 SYNCHRONIZE,    "SYNCHRONIZE",
 STANDARD_RIGHTS_REQUIRED,  "STANDARD_RIGHTS_REQUIRED",
 STANDARD_RIGHTS_READ,      "STANDARD_RIGHTS_READ",
 STANDARD_RIGHTS_WRITE,     "STANDARD_RIGHTS_WRITE",
 STANDARD_RIGHTS_EXECUTE,   "STANDARD_RIGHTS_EXECUTE",
 STANDARD_RIGHTS_ALL,       "STANDARD_RIGHTS_ALL",
 ACCESS_SYSTEM_SECURITY,    "ACCESS_SYSTEM_SECURITY",
 MAXIMUM_ALLOWED,           "MAXIMUM_ALLOWED",
 GENERIC_READ,              "GENERIC_READ",
 GENERIC_WRITE,             "GENERIC_WRITE",
 GENERIC_ALL,               "GENERIC_ALL",
 FILE_READ_DATA,            "FILE_READ_DATA",
 FILE_LIST_DIRECTORY,       "FILE_LIST_DIRECTORY",
 FILE_WRITE_DATA,           "FILE_WRITE_DATA",
 FILE_ADD_FILE,             "FILE_ADD_FILE",
 FILE_APPEND_DATA,          "FILE_APPEND_DATA",
 FILE_ADD_SUBDIRECTORY,     "FILE_ADD_SUBDIRECTORY",
 FILE_CREATE_PIPE_INSTANCE, "FILE_CREATE_PIPE_INSTANCE",
 FILE_READ_EA,              "FILE_READ_EA",
 FILE_WRITE_EA,             "FILE_WRITE_EA",
 FILE_EXECUTE,              "FILE_EXECUTE",
 FILE_TRAVERSE,             "FILE_TRAVERSE",
 FILE_DELETE_CHILD,         "FILE_DELETE_CHILD",
 FILE_READ_ATTRIBUTES,      "FILE_READ_ATTRIBUTES",
 FILE_WRITE_ATTRIBUTES,     "FILE_WRITE_ATTRIBUTES",
 FILE_ALL_ACCESS,           "FILE_ALL_ACCESS",
 FILE_GENERIC_READ,         "FILE_GENERIC_READ",
 FILE_GENERIC_WRITE,        "FILE_GENERIC_WRITE",
 FILE_GENERIC_EXECUTE,      "FILE_GENERIC_EXECUTE"
);

_field_names = make_list();
foreach f (perm_array)
  _field_names[max_index(_field_names)] = f;
perm_pad_size = maxlen(_field_names);




function perm_item ()
{
  local_var key, setting, dword;
  key      = _FCT_ANON_ARGS[0];
  dword    = _FCT_ANON_ARGS[1];
  if (dword & key) setting = 'YES';
  else setting = 'NO';
  return '    '+perm_array[key] + ': ' +
         crap(data:' ', 
              length:(perm_pad_size-strlen(perm_array[key]))) +
         setting;
}

function permissions (verbose)
{
  local_var field, fields, report, settings, dword;
  dword    = _FCT_ANON_ARGS[0];
  if (!isnull(verbose) && verbose == 2) # 2 means 'Verbose'
    fields = keys(perm_array);
  else
    fields = [FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE];
  settings = make_list();
  foreach field (fields)
    settings[max_index(settings)] = perm_item(dword, field);
  report   = '\n'+join(settings, sep:'\n');
  return report;
}

login    = kb_smb_login();
pass     = kb_smb_password();
dom      = kb_smb_domain();
port     = kb_smb_transport();
smb_name = kb_smb_name();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
ret = NetUseAdd(login:login, password:pass, domain:dom, share:"IPC$");
if (ret != 1)
  audit(AUDIT_SHARE_FAIL, 'IPC$');

shares = NetShareEnum(level:SHARE_INFO_502);
sharecount = 0;

if (isnull(shares))
{
  NetUseDel();
  audit(code:1, AUDIT_FN_FAIL, 'NetShareEnum');
}

lsa = LsaOpenPolicy(desired_access:0x20801);
if (isnull(lsa))
{
  NetUseDel();
  audit(code:1, AUDIT_FN_FAIL, 'LsaOpenPolicy');
}

report = NULL;
num_shares = 0;  # number of shares with SDs
foreach share (shares)
{
  
  sharecount += 1;

  sd = share[9];
  if (isnull(sd)) continue;
  else num_shares++;

  owner = sid2string(sid:sd[0]);
  group = sid2string(sid:sd[1]);
  dacl = parse_pdacl(blob:sd[3]);
  if (isnull(dacl)) continue;

  report +=
    '\nShare path : \\\\' + smb_name + '\\' + share[0] +
    '\nLocal path : ' + share[6];

  if (share[2])
    report += '\nComment : ' + share[2];

  if (max_index(dacl) == 0)
    report += '\nACEs : None';

  foreach ace (dacl)
  {
    ace = parse_dacl(blob:ace);
    if (isnull(ace)) continue;

    rights = ace[0];

    type = ace[3];
    sids = make_list(ace[1]);

    names = LsaLookupSid(handle:lsa, sid_array:sids);
    if (isnull(names)) continue;

    name_info = parse_lsalookupsid(data:names[0]);
    if (isnull(name_info[1]))
      name = name_info[2];
    else
      name = name_info[1] + '\\' + name_info[2];
    
    report += '\n[*] ';
    if (type == ACCESS_DENIED_ACE_TYPE)
      report += 'Deny ACE ';
    else if (type == ACCESS_ALLOWED_ACE_TYPE)
      report += 'Allow ACE ';
    else
      continue; #unexpected
  
    report += 'for ' + name + ': 0x'+int2hex(rights, width:8);
    report += permissions(rights, verbose:report_verbosity);

  }
  report += '\n';
}
LsaClose(handle:lsa);
NetUseDel();

if (num_shares == 0)
  exit(0, 'No shares with security descriptor were enumerated on the remote host.');
else if (isnull(report))
  exit(1, 'Unknown error trying to enumerate share permissions.');

security_note(port:port, extra:report);


#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(46742);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_name(english:"Microsoft Windows SMB Registry : Enumerate the list of SNMP communities");
  script_summary(english:"Extracts the list of SNMP communities");

 script_set_attribute(attribute:"synopsis", value:"The remote Windows host one or more SNMP communities configured");
 script_set_attribute(attribute:"description", value:
"Using the registry, it was possible to extract the list of SNMP
communities configured on the remote host. You should ensure that each
community has the appropriate permission and that it can not be
guessed by an attacker");
 script_set_attribute(attribute:"solution", value:"None");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/27");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");

function snmp_perm()
{
 local_var t;
 local_var ret;

 t = _FCT_ANON_ARGS[0];
 if ( t & 1 ) return "NONE";
 if ( t & 2 ) return "NOTIFY";
 if ( t & 4 ) return "READ ONLY";
 if ( t & 8 ) return "READ WRITE";
 if ( t & 16 ) return "READ CREATE";
 return "?";
}


#if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
port = kb_smb_transport();
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}


hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

report = "";
num_communities = 0;
key = "SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # Grab installed version(s) of AIM (listed as subkeys of 'key_h').
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[0]; ++i)
  {
    num_communities++;
    entries[i] = RegEnumValue(handle:key_h, index:i);
    k = entries[i];
    value  = RegQueryValue(handle:key_h, item:k[1]);
    report += '\n  - Community name : \'' + k[1] + '\'' +
              '\n    Permissions    : ' + snmp_perm(value[1]) + '\n';
  }
 RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();

if ( strlen(report) > 0 )
{
 report =
'\nUsing the registry, it was possible to gather the following
information about SNMP communities configured on the remote host :\n' + report;

 security_note(port:kb_smb_transport(), extra:report);
}

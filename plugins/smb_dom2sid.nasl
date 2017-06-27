#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10398);
 script_version("$Revision: 1.52 $");
 script_cvs_date("$Date: 2016/11/15 13:33:21 $");

 script_cve_id("CVE-2000-1200");
 script_bugtraq_id(959);
 script_osvdb_id(715);

 script_name(english:"Microsoft Windows SMB LsaQueryInformationPolicy Function NULL Session Domain SID Enumeration");
 script_summary(english:"Gets the domain SID.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain the domain SID.");
 script_set_attribute(attribute:"description", value:
"By emulating the call to LsaQueryInformationPolicy(), it was possible
to obtain the domain SID (Security Identifier).

The domain SID can then be used to get the list of users of the
domain.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_dependencies("smb_scope.nasl", "netbios_name_get.nasl", "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/test_domain");
 script_require_ports(139, 445);

 exit(0);
}


include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");

d = get_kb_item("SMB/test_domain");
if(! d)
  exit(0, 'The scan policy is not configured to request domain information. ' +
          'Please see Preferences/SMB Scope.');

port = kb_smb_transport();
if(!port)port = 445;

login = kb_smb_login();
pass  = kb_smb_password();

if(!login)login = "";
if(!pass) pass = "";

dom = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

ret = NetUseAdd (login:login, password:pass, domain:dom, share:"IPC$");
if ( ret != 1 ) audit(AUDIT_SHARE_FAIL, 'IPC$');

handle = LsaOpenPolicy (desired_access:0x20801);
if (isnull(handle))
{
  NetUseDel ();
  audit(AUDIT_FN_FAIL, 'LsaOpenPolicy');
}

ret = LsaQueryInformationPolicy (handle:handle, level:PolicyPrimaryDomainInformation);
if (isnull (ret))
{
 LsaClose (handle:handle);
 NetUseDel ();
 audit(AUDIT_FN_FAIL, 'LsaQueryInformationPolicy');
}

sid = ret[1];
primary_domain = ret[0];

LsaClose (handle:handle);
NetUseDel ();

if(primary_domain)
  set_kb_item(name:"SMB/primary_domain", value:primary_domain);

if(strlen(sid) != 0)
{
 set_kb_item(name:"SMB/domain_sid", value:hexstr(sid));

 report = string (
		"The remote domain SID value is :\n",
		sid2string(sid:sid));

 security_note(extra:report, port:port);
}
else exit(0, 'Failed to obtain domain SID, remote host may not be a domain member.');

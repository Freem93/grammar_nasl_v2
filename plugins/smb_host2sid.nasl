#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10859);
 script_version("$Revision: 1.43 $");
 script_cvs_date("$Date: 2015/11/18 21:03:58 $");

 script_cve_id("CVE-2000-1200");
 script_bugtraq_id(959);
 script_osvdb_id(715);

 script_name(english:"Microsoft Windows SMB LsaQueryInformationPolicy Function SID Enumeration");
 script_summary(english:"Gets the host SID");

 script_set_attribute(attribute:"synopsis", value:"It is possible to obtain the host SID for the remote host.");
 script_set_attribute(attribute:"description", value:
"By emulating the call to LsaQueryInformationPolicy(), it was possible
to obtain the host SID (Security Identifier).

The host SID can then be used to get the list of local users.");

 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/library/bb418944.aspx");
 script_set_attribute(attribute:"solution", value:
"You can prevent anonymous lookups of the host SID by setting the
'RestrictAnonymous' registry setting to an appropriate value.

Refer to the 'See also' section for guidance.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/02/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("netbios_name_get.nasl", "smb_login.nasl","smb_hotfixes.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_require_ports(139, 445);
 exit(0);
}

#

include("audit.inc");
include("smb_func.inc");

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

ret = LsaQueryInformationPolicy (handle:handle, level:PolicyAccountDomainInformation);
if (isnull (ret))
{
 LsaClose (handle:handle);
 NetUseDel ();
 audit(AUDIT_FN_FAIL, 'LsaQueryInformationPolicy');
}

sid = ret[1];
account_domain = ret[0];

LsaClose (handle:handle);
NetUseDel ();

if(account_domain)
 set_kb_item(name:"SMB/account_domain", value:account_domain);

if(strlen(sid) != 0)
{
 set_kb_item(name:"SMB/host_sid", value:hexstr(sid));

 ra = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/LSA/RestrictAnonymous");
 if(isnull(ra)) ra = "unknown";

 report = string (
		"\nThe remote host SID value is :\n\n",
		sid2string(sid:sid),"\n",
                "\n",
                "The value of 'RestrictAnonymous' setting is : ", ra,
                "\n");

 security_note(extra:report, port:port);
}
else exit(1, 'Failed to obtain host SID.');

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(56210);
 script_version("$Revision: 1.3 $");
 script_cvs_date("$Date: 2014/04/11 19:55:53 $");

 script_cve_id("CVE-2000-1200");
 script_bugtraq_id(959);
 script_osvdb_id(715);

 script_name(english:"Microsoft Windows SMB LsaQueryInformationPolicy Function SID Enumeration Without Credentials");
 script_summary(english:"Gets the host SID without credentials");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the host SID for the remote host, without
credentials.");
 script_set_attribute(attribute:"description", value:
"By emulating the call to LsaQueryInformationPolicy(), it was possible
to obtain the host SID (Security Identifier), without credentials.

The host SID can then be used to get the list of local users.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/library/bb418944.aspx");
 script_set_attribute(attribute:"solution", value:
"You can prevent anonymous lookups of the host SID by setting the
'RestrictAnonymous' registry setting to an appropriate value.

Refer to the 'See also' section for guidance.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/31");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/15");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("netbios_name_get.nasl", "smb_login.nasl","smb_hotfixes.nasl");
 script_exclude_keys("SMB/not_windows");
 script_require_keys("SMB/transport", "SMB/name", "SMB/null_session_enabled");
 script_require_ports(139, 445);
 exit(0);
}

include("audit.inc");
include("smb_func.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

port = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

name = kb_smb_name();
if (!login) login = "";
if (!pass) pass = "";
dom = kb_smb_domain();

session_init (socket:soc,hostname:name);
ret = NetUseAdd (login:login, password:pass, domain:dom, share:"IPC$");
if (ret != 1)
{
 close(soc);
 audit(AUDIT_SHARE_FAIL, "IPC$");
}

handle = LsaOpenPolicy (desired_access:0x20801);
if (isnull(handle))
{
  NetUseDel ();
  exit(0);
}

ret = LsaQueryInformationPolicy (handle:handle, level:PolicyAccountDomainInformation);
if (isnull (ret))
{
 LsaClose (handle:handle);
 NetUseDel ();
 exit (0);
}

sid = ret[1];

LsaClose (handle:handle);
NetUseDel ();

if(strlen(sid) != 0)
{
 set_kb_item(name:"SMB/null_session/host_sid", value:hexstr(sid));

 report = string (
		"\nThe remote host SID value is :\n\n",
		sid2string(sid:sid),"\n",
                "\n"
                );

 security_warning(extra:report, port:port);
}

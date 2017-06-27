#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24786);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2013/01/07 14:19:59 $");

 script_name(english:"Nessus Windows Scan Not Performed with Admin Privileges");
 script_summary(english:"Connects to ADMIN$");
 
 script_set_attribute(attribute:"synopsis", value:
"The Nessus scan of this host may be incomplete due to insufficient
privileges provided.");
 script_set_attribute(attribute:"description", value:
"The Nessus scanner testing the remote host has been given SMB
credentials to log into the remote host, however these credentials do
not have administrative privileges. 

Typically, when Nessus performs a patch audit, it logs into the remote
host and reads the version of the DLLs on the remote host to determine
if a given patch has been applied or not.  This is the method Microsoft
recommends to determine if a patch has been applied. 

If your Nessus scanner does not have administrative privileges when
doing a scan, then Nessus has to fall back to perform a patch audit
through the registry which may lead to false positives (especially when
using third-party patch auditing tools) or to false negatives (not all
patches can be detected through the registry).");
 script_set_attribute(attribute:"solution", value:
"Reconfigure your scanner to use credentials with administrative
privileges.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
 script_family(english:"Settings");

 script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
 script_exclude_keys("SMB/not_windows");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/transport");
 script_require_ports(139, 445);
 exit(0);
}

include("audit.inc");
include("smb_func.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

port = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

name = kb_smb_name();
login = kb_smb_login();
password = kb_smb_password();
domain   = kb_smb_domain();

soc = open_sock_tcp (port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:password, domain:domain, share:"IPC$");
if ( r != 1 ) audit(AUDIT_SHARE_FAIL, 'IPC$');
NetUseDel(close:FALSE);

r = NetUseAdd(login:login, password:password, domain:domain, share:"ADMIN$");
NetUseDel();
if ( r != 1 ) security_note(port:0, extra:'\n' + "It was not possible to connect to '\\"+name+"\ADMIN$' with the supplied credentials."+'\n');
else exit(0, "It was possible to connect to '\\"+name+"\ADMIN$' with the supplied credentials.");

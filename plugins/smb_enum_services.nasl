#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10456);
 script_version("$Revision: 1.42 $");
 script_cvs_date("$Date: 2015/01/12 17:12:47 $");

 script_name(english:"Microsoft Windows SMB Service Enumeration");
 script_summary(english:"Enumerates the list of remote services");

 script_set_attribute(attribute:"synopsis", value:"It is possible to enumerate remote services.");
 script_set_attribute(attribute:"description", value:
"This plugin implements the SvcOpenSCManager() and SvcEnumServices()
calls to obtain, using the SMB protocol, the list of active and
inactive services of the remote host.

An attacker may use this feature to gain better knowledge of the
remote host.");
 script_set_attribute(attribute:"solution", value:
"To prevent the listing of the services from being obtained, you should
either have tight login restrictions, so that only trusted users can
access your host, and/or you should filter incoming traffic to this
port.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/07/03");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
 script_exclude_keys("SMB/not_windows");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_require_ports(139, 445);
 exit(0);
}


include("audit.inc");
include("smb_func.inc");


if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

port = kb_smb_transport();
login = kb_smb_login();
pass  = kb_smb_password();
dom = kb_smb_domain();

if(!login)login = "";
if(!pass) pass = "";

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

ret = NetUseAdd (login:login, password:pass, domain:dom, share:"IPC$");
if (ret != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, 'IPC$', code:0);
}


handle = OpenSCManager (access_mode:SC_MANAGER_ENUMERATE_SERVICE);
if (isnull (handle))
{
  NetUseDel();
  audit(AUDIT_FN_FAIL, "OpenSCManager");
}

active_list = EnumServicesStatus (handle:handle, type:SERVICE_WIN32, state:SERVICE_ACTIVE);
inactive_list = EnumServicesStatus (handle:handle, type:SERVICE_WIN32, state:SERVICE_INACTIVE);

CloseServiceHandle (handle:handle);
NetUseDel ();

if (isnull (active_list) && isnull(inactive_list))
  exit (1, "No services were detected.");

services = NULL;
active_services = NULL;
inactive_services = NULL;

foreach elem (active_list)
{
 parse = GetService (service:elem);
 active_services += parse[1] + " [ " + parse[0] + ' ] \n';
 set_kb_item(name:"SMB/svc/" + parse[0], value:SERVICE_ACTIVE);
 set_kb_item(name:"SMB/svc/" + parse[0] + "/display_name", value:parse[1]);
}

if (max_index(active_list) > 0)
{
 services += '\nActive Services :\n\n' + active_services;
 set_kb_item(name:"SMB/svcs", value:active_services);
}

foreach elem (inactive_list)
{
 parse = GetService (service:elem);
 inactive_services += parse[1] + " [ " + parse[0] + ' ] \n';
 set_kb_item(name:"SMB/svc/" + parse[0], value:SERVICE_INACTIVE);
 set_kb_item(name:"SMB/svc/" + parse[0] + "/display_name", value:parse[1]);
}

if (max_index(inactive_list) > 0)
{
 services += '\nInactive Services :\n\n' + inactive_services;
 set_kb_item(name:"SMB/svcs/inactive", value:inactive_services);
}

set_kb_item(name:"SMB/Services/Enumerated", value:TRUE);

if (services) security_note(extra: services, port:port);

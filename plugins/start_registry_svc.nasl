#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

include("compat.inc");

if (description)
{
 script_id(35703);
 script_version("$Revision: 1.9 $");
 script_cvs_date("$Date: 2015/11/25 15:32:52 $");
 
 script_name(english:"SMB Registry : Start the Registry Service during the scan");
 script_summary(english:"Determines whether the remote registry service is running");
 
 script_set_attribute(attribute:"synopsis", value:
"The registry service was enabled for the duration of the scan.");
 script_set_attribute( attribute:"description",  value:
"To perform a full credentialed scan, Nessus needs the ability to
connect to the remote registry service (RemoteRegistry).  If the
service is down, this plugin will attempt to start for the duration of
the scan. 

You need to explicitely set the option 'Start the Registry Service',
'Advanced->Start the Registry' for this plugin to work.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/18");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
 script_family(english:"Settings");
 if ( NASL_LEVEL < 4000 )
  script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
 else
  script_dependencies("wmi_start_registry_svc.nbin");

 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_exclude_keys("SMB/not_windows");
 script_add_preference(name:"Start the registry service during the scan", type:"checkbox", value:"no");
 script_add_preference(name:"Enable administrative shares during the scan", type:"checkbox", value:"no");
 script_require_ports(139, 445);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");

if ( NASL_LEVEL >= 4000 ) exit(0); # wmi_start_registry_svc.nbin did the job already

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

opt = script_get_preference("Start the registry service during the scan");
if ( opt != "yes" ) exit(0);

name	= kb_smb_name();
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

logged = 0;

replace_kb_item(name:"SMB/remote_registry_last_access", value:unixtime());

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r == 1 )
{
  handle = OpenSCManager (access_mode:SC_MANAGER_ALL_ACCESS);
  if ( !isnull(handle) )
  {
     shandle = OpenService (handle:handle, service:"RemoteRegistry", access_mode:MAXIMUM_ALLOWED);
     if ( !isnull(handle) )
     {
       status = QueryServiceStatus (handle:shandle);
       if ( ! isnull(status) )
	{
	if ( status[1] == SERVICE_STOPPED )
         {
 	   ret = StartService (handle:shandle);
	   if ( ret == 1 ) 
		{
		security_note(port:0, extra:"The registry service was successfully started for the duration of the scan");
	   	set_kb_item(name:"SMB/shutdown_registry_after_scan", value:TRUE);
		}
         } 
	}
	 else err = "Could not query the service status";
        CloseServiceHandle (handle:shandle);
     } else err = "Could not open RemoteRegistry";
   CloseServiceHandle (handle:handle);
  } else err = "OpenSCManager() failed";
 NetUseDel();
}
else err = "NetUseAdd failed";

if ( strlen(err) )
{
 set_kb_item(name:"SMB/start_registry/failed", value:err);
}

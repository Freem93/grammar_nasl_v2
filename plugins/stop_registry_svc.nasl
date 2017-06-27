#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(35704);
 script_version ("$Revision: 1.10 $");
 
 name["english"] = "SMB Registry : Stop the Registry Service after the scan";
 script_name(english:name["english"]);
 
  script_set_attribute( attribute:"synopsis", value:
"The registry service was stopped after the scan."  );
  script_set_attribute( attribute:"description",   value:
"To perform a full credentialed scan, Nessus needs the ability to connect to
the remote registry service (RemoteRegistry). If the service is down and if
Nessus automatically enabled the registry for the duration of the scan,
this plugin will stop it afterwards."  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  if ( NASL_LEVEL >= 4000 ) script_set_attribute(attribute:"always_run", value:TRUE);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/18");
 script_cvs_date("$Date: 2012/07/09 16:36:52 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

 
 
 summary["english"] = "Determines whether the remote registry service was started by nessusd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_END);
 
 script_copyright(english:"This script is Copyright (C) 2009-2012 Tenable Network Security, Inc.");
 family["english"] = "Settings";
 script_family(english:family["english"]);
 
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/shutdown_registry_after_scan");
 if ( NASL_LEVEL >= 4000 )
  script_dependencies("wmi_stop_registry_svc.nbin");
 script_require_ports(139, 445);
 script_exclude_keys("Host/dead");
 exit(0);
}

include("smb_func.inc");
if ( NASL_LEVEL >= 4000 ) exit(0); # wmi_stop_registry_svc.nbin did the job already

if (!get_kb_item("SMB/shutdown_registry_after_scan")) exit(0);
if ( get_kb_item("Host/dead") ) exit(0);

port = kb_smb_transport();
if(!port)port = 139;

name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

soc = open_sock_tcp(port);
if ( ! soc ) {
  set_kb_item(name:"SMB/stop_registry/failed", value:"Could not connect to port " + port);
  exit(0);
}

logged = 0;

session_init(socket:soc, hostname:name);
err = NULL;
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
       if ( ! isnull(status) && status[1] == SERVICE_RUNNING )
        {
 	   ret = ControlService(handle:shandle, control:SERVICE_CONTROL_STOP);
	   if ( ret == 1 ) 
		{
		security_note(port:0, extra:"The registry service was successfully stopped after the scan");
		}
	   else err = "StopService() failed";
        }
        CloseServiceHandle (handle:shandle);
     }
     else err = "OpenService() failed";
   CloseServiceHandle (handle:handle);
  }
  else err = "OpenSCManager() failed";
 NetUseDel();
}
else err = "Could not connect to IPC$";

if ( strlen(err) ) set_kb_item(name:"SMB/stop_registry/failed", value:err);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(21745);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2014/11/10 16:36:17 $");

 script_name(english:"Authentication Failure - Local Checks Not Run");
 script_summary(english:"Displays information about the scan");

 script_set_attribute(attribute:"synopsis", value:"The local security checks are disabled.");
 script_set_attribute(attribute:"description", value:
"Local security checks have been disabled for this host because either
the credentials supplied in the scan policy did not allow Nessus to
log into it or some other problem occurred.");
 script_set_attribute(attribute:"solution", value:"Address the problem(s) so that local security checks are enabled.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/23");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_END);
 script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
 script_family(english:"Settings");

 # No dependencies, since this is an ACT_END plugin
 exit(0);
}


include("smb_func.inc");
global_var report;


function check_svc(svc, port_name, default)
{
 local_var port, soc;
 local_var msg, os, os_confidence, err;

 if ( get_kb_item("HostLevelChecks/" + svc + "/failed") )
 {
  if ( !isnull(port_name) )
	port = get_kb_item(port_name);

  if ( ! port ) port = default;
  if ( get_port_state(port) )
  {
   soc = open_sock_tcp(port);
   if ( soc )
	{
         close(soc);
         msg = get_kb_item("HostLevelChecks/"+svc+"/error_msg");
         if (isnull(msg)) msg = 'It was not possible to log into the remote host via '+svc+' (invalid credentials).';
 	 report += '- ' + msg + '\n';
	}
  }
 }
 else if ( svc == "smb" && !get_kb_item("Host/local_checks_enabled") && get_kb_item("SMB/login_filled/0") )
 {
   #
   # https://discussions.nessus.org/message/11795#11795 -- for Windows systems, if credentials have been
   # supplied we should warn that we could not log in, even if port 139/445 is unreachable.
   #
   # - If it's Windows
   # - And we're sure of it
   # - And no SMB/login key is present (yet SMB/login_filled/0 was set)
   # - Then do an alert
   #
   os = get_kb_item("Host/OS");
   os_confidence = get_kb_item("Host/OS/Confidence");
   if ( !isnull(os) && os_confidence > 65 && "Windows" >< os && !get_kb_item("SMB/login") )
   {
	 # Let's try to find out why we could not connect
	 if ( defined_func("socket_get_error") )
 	 {
          port = default;
	  soc = open_sock_tcp(port, nonblocking:TRUE);
          if (soc)
          {
            while (  socket_ready(soc) == 0 ) usleep(50000);
            err = socket_get_error(soc);
            close(soc);
          }
          if ( !soc ) err = "(unable to create a socket)";
    	  else if ( err == ETIMEDOUT ) err = "(connection timed out)";
    	  else if ( err == EUNREACH ) err = "(service is unreachable)";
    	  else if ( err == ECONNREFUSED ) err = "(port closed)";
    	  else err = "(protocol failed)";
	 }
	 else err = "(could not contact service)";

 	 report += '- It was not possible to log into the remote host via ' + svc + ' ' + err + '.\n';
   }
 }
}


if ( ( str = get_kb_item("HostLevelChecks/failure") )  )
{
  report += 'The local checks failed because :\n' + str + '\n';
}

if ( get_kb_item("Host/local_checks_enabled") && ! report ) exit(0);

check_svc(svc:"ssh", default:22);
check_svc(svc:"telnet", port_name:"Services/telnet", default:23);
check_svc(svc:"rexec", port_name:"Services/rexec", default:513);
check_svc(svc:"rlogin", port_name:"Services/rlogin", default:513);
check_svc(svc:"rsh", port_name:"Services/rsh", default:514);
check_svc(svc:"smb", default:kb_smb_transport());




if ( report )
{
 security_note(port:0, extra:report);
}

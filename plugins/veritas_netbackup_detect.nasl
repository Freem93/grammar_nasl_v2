#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(20148);
 script_version ("$Revision: 1.13 $");
 script_cvs_date("$Date: 2011/03/11 21:18:10 $");

 script_name(english:"VERITAS NetBackup Agent Detection");

 script_set_attribute(attribute:"synopsis", value:
"A backup software is running on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the VERITAS NetBackup Java Console
service. This service is used by the NetBackup Java Console 
GUI to manage the backup server. A user, authorized to connect 
to this service, can use it as a remote shell with system 
privileges by sending 'command_EXEC_LIST' messages." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/07");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Determine if a remote host is running VERITAS NetBackup Java Service");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_require_ports (13722, 13724, "Services/unknown");
 exit(0);
}

include ("global_settings.inc");
include ("misc_func.inc");


function check (port, socket, line)
{
 local_var data, version, report;

 if (egrep(pattern:"^NetBackup .* - bpjava-.*svc.*", string:line))
 {
  # command_US_SHUTDOWN
  data = ' 99 1\nbpjava-msvc\n';
  send (socket:socket, data:data);

  close (socket);

  version = ereg_replace (pattern:"^NetBackup (.*) - bpjava-.*svc.*", string:line, replace:"\1");
  report = string ("\n",
		  "Remote version of NetBackup is : ",
		  version);

  security_note (port:port, extra:report);
  set_kb_item (name:"VERITAS/NetBackupJavaAgent", value:port);
  if (service_is_unknown(port:port))
      register_service(port:port, ipproto:"tcp", proto:"VeritasNetBackup");
 }
}



function check_version (socket, port)
{
 local_var data, line;

 # command_SERVER_VERSION
 data = ' 116 1\nnessus\n';
 send (socket:socket, data:data);

 line = recv_line (socket:socket, length:4096);
 if (!egrep (pattern:"^ 116 ", string:line))
   exit (0);

 line = recv_line (socket:socket, length:4096);

 check (socket:socket, port:port, line:line);
}


function init_protocol (socket)
{
 local_var req, ret;

 req = '4\0';
 send (socket:socket, data:req);
 ret = recv (socket:socket, length:2, min:2);
 if (ret != req)
   return 0;

 send (socket:socket, data:req);

 req = '6\0bpjava-msvc\0';
 send (socket:socket, data:req);
 ret = recv (socket:socket, length:2, min:2);
 if (ret != '0\0')
   return 0;

 return 1;
}


port = 13722;
if (get_port_state(port))
{
 soc = open_sock_tcp (port);
 if (soc)
   check_version (socket:soc, port:port);
}

port = 13724;
if (get_port_state(port))
{
 soc = open_sock_tcp (port);
 if (soc)
 {
  ret = init_protocol (socket:soc);
  if (ret == 1)
    check_version (socket:soc, port:port);
 }
}


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
 port = get_unknown_svc();
 if ((port == 13724) || (port == 13722) || ! port) exit (0);

 port = port;
 if (get_port_state(port))
 {
  soc = open_sock_tcp (port);
  if (soc)
    check_version (socket:soc, port:port);

  soc = open_sock_tcp (port);
  if (soc)
  {
   ret = init_protocol (socket:soc);
   if (ret == 1)
     check_version (socket:soc, port:port);
  }
 }
}

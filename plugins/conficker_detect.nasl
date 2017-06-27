#
# (C) Tenable Network Security, Inc.
#

# Credit: Felix Leder & Tillmann Werner, Dan Kaminsky
# http://net.cs.uni-bonn.de/wg/cs/applications/containing-conficker/
#
# Version 3 : added support for Conficker.E
#

include("compat.inc");
if(description)
{
 script_id(36036);
 script_version("$Revision: 3.12 $");
 script_name(english:"Conficker Worm Detection (uncredentialed check)");
 script_set_attribute(attribute:"synopsis", value:"The remote host seems to be infected by a variant of the Conficker worm.");
 script_set_attribute(attribute:"description", value:"
The remote host seems to be infected by the Conficker worm. This worm
has several capabilities which allow an attacker to execute arbitrary code
on the remote operating system. 
The remote host might also be attempting to propagate the worm to third
party hosts.");
 script_set_attribute(attribute:"solution", value:"
Update your Antivirus and perform a full scan of the remote operating system.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"see_also", value:"http://net.cs.uni-bonn.de/wg/cs/applications/containing-conficker/");
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/962007");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f3900d3");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/03/29");
 script_cvs_date("$Date: 2017/05/16 19:35:38 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

 script_summary(english:"Determines the presence of the conficker worm");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");
 script_dependencies("netbios_name_get.nasl", "cifs445.nasl", "smb_login.nasl");
 script_require_ports(139, 445);
 exit(0);
}

#

include ('smb_func.inc');
include ('global_settings.inc');

global_var fid, log_msg;

function  ConfickerC_Detect()
{
 local_var data, data2, fid2, rep, ret;
 local_var pipe, pipes;
 local_var vector;

 pipes = make_list('\\browser', '\\wkssvc', '\\srvsvc');

 foreach pipe ( pipes )
 {
  fid = bind_pipe (pipe:pipe, uuid:"4b324fc8-1670-01d3-1278-5a47bf6ee188", vers:3);
  if ( ! isnull(fid) ) break;
 }
 if (isnull (fid)) 
 {
   log_msg = strcat('Could not bind to \\browser, \\wkssvc nor \\srvsvc\n');
   return -1;
 }

 fid2 = NULL;
 if ( pipe != '\\srvsvc' ) fid2 = bind_pipe (pipe:pipe, uuid:"6bffd098-a112-3610-9833-46c3f87e345a", vers:1);
 if ( ! isnull(fid2) ) 
 {
  vector = "NetPathCompare()";
  data2 = class_parameter (name:"", ref_id:0x20000) +
          class_name (name:crap(data:"\A", length:0x100)) +
  	  raw_dword (d:0) ;
 
  data = class_parameter (name:"", ref_id:0x20000) +
        class_name (name:"\" + crap(data:"B", length:0x23) + "\..\nessus") +
	class_name (name:"\nessus") + 
	raw_dword (d:1) +
	raw_dword (d:0) ;
 
  data2 = dce_rpc_pipe_request (fid:fid2, code:0x0A, data:data2);
  if (!data2)
  {
   log_msg = strcat('dce_rpc_pipe_request(1) failed\n');
   return -1;
  }

  data = dce_rpc_pipe_request (fid:fid, code:0x20, data:data);
  if (!data)
  {
   log_msg = strcat('dce_rpc_pipe_request(2) failed\n');
   return -1;
  }
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen(rep) != 4))
 {
  log_msg = strcat('Bad response type ', strlen(rep), '\n');
  return -1;
 }
 }
 else
 {
  vector = "NetPathCanonicalize()";
  data = class_parameter (name:"a", ref_id:0x00001) +
        class_name(name:"\..\") +
	raw_dword (d:2) +
	class_name (name:"\") + 
	raw_dword (d:1) +
	raw_dword (d:1) ;
 data = dce_rpc_pipe_request (fid:fid, code:0x1f, data:data);
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen(rep) != 16))
 {
  log_msg = strcat('Bad response type ', strlen(rep), '\n');
  return -1;
 }
 }
  
 ret = get_dword (blob:rep, pos:strlen(rep)-4);
 if (ret == 87 )
 {
   log_msg = strcat('host is INFECTED (checked via ', vector, '\n');
   return 1;
 }

 log_msg = strcat('host is clean (checked via ' + vector + ')\n');
 return 0;
}

function  ConfickerD_Detect()
{
 local_var data, rep, ret1, ret2;

 data = class_parameter (name:"a", ref_id:0x00001) +
        class_name(name:"\") +
        raw_dword (d:2) +
        class_name (name:"\") + 
        raw_dword (d:1) +
        raw_dword (d:1) ;
 data = dce_rpc_pipe_request (fid:fid, code:0x1f, data:data);
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen(rep) != 16))
 {
  log_msg = strcat('Bad response type ', strlen(rep), '\n');
  return -1;
 }
 ret1 = get_dword (blob:rep, pos:strlen(rep)-12);
 ret2 = get_dword (blob:rep, pos:strlen(rep)-4);
 if ( (ret1 == 0x5c45005c || ret1 == 0) && ret2 == 0 )
 {
   log_msg = strcat('host is INFECTED\n');
   return 1;
 }

 log_msg = strcat('host is clean\n');
 return 0;
}



os = get_kb_item ("Host/OS/smb") ;
#if ("Windows" >!< os) exit(0);

name	= kb_smb_name();
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(1, strcat('Could not connect to port ', port, '\n')); 

session_init(socket:soc, hostname:name);
login = kb_smb_login();
password = kb_smb_password();

if ( login && password )
 r = NetUseAdd(share:"IPC$", login:login, password:password, domain:kb_smb_domain());
else
 r = NetUseAdd(share:"IPC$");
if ( r == 1 )
{
 ret = ConfickerC_Detect();
 if (ret == 1)
   security_hole(port:port, extra:"The remote host is infected by Conficker.A, Conficker.B or Conficker.C");
 else if ( ret == 0 )
 {
  ret = ConfickerD_Detect();
  if (ret == 1) security_hole(port:port, extra:"The remote host is infected by Conficker.D/Conficker.E");
  else if ( ret == 0 ) exit(0, log_msg);
  else if ( ret < 0 ) exit(1, log_msg);
 }
 else if ( ret < 0 ) exit(1, log_msg);
 NetUseDel();
}
else exit(1, 'Could not connect to IPC$\n');

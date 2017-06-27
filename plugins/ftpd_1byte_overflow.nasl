#
# (C) Tenable Network Security, Inc.
#

# This script was written by Xue Yong Zhi <yong@tenablesecurity.com>

include("compat.inc");

if (description)
{
 script_id(11371);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2014/05/26 00:06:13 $");

 script_cve_id("CVE-2001-0053");
 script_bugtraq_id(2124);
 script_osvdb_id(1693);

 script_name(english:"BSD ftpd Single Byte Buffer Overflow");
 script_summary(english:"Checks if the remote ftpd can be buffer overflown");

 script_set_attribute(attribute:"synopsis", value:"The remote ftp server is affected by a buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote ftp daemon contains a flaw in the 'replydirname()' function
which allows an attacker to write a null byte beyond the boundaries of
the local buffer. An attacker can exploit this to gain root access.");
 script_set_attribute(attribute:"see_also", value:"http://www.openbsd.org/advisories/ftpd_replydirname.txt");
 script_set_attribute(attribute:"see_also", value:"ftp://ftp.openbsd.org/pub/OpenBSD/patches/2.8/common/005_ftpd.patch" );
 script_set_attribute(attribute:"solution", value:"Apply the fix from the references above.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/12/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/13");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");

 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_writeable_directories.nasl");
 script_require_keys("ftp/login", "ftp/writeable_dir", "Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# First, we need anonymous access

login = get_kb_item_or_exit("ftp/login");
pass  = get_kb_item("ftp/password");

port = get_ftp_port(default: 21);

# Then, we need a writeable directory
wri = get_kb_item("ftp/"+port+"/writeable_dir");
if (! wri) wri = get_kb_item_or_exit("ftp/writeable_dir");

nomkdir = get_kb_item("ftp/"+port+"/no_mkdir");
if(nomkdir)exit(0);

global_var num_dirs;

function clean_exit()
{
  local_var j, r, soc;

  soc = open_sock_tcp(port);
  if ( soc )
  {
  ftp_authenticate(socket:soc, user:login, pass:pass);
  send(socket:soc, data: strcat('CWD ', wri, '\r\n'));
  r = ftp_recv_line(socket:soc);
  for(j=0;j<num_dirs - 1;j=j+1)
  {
   send(socket:soc, data: strcat('CWD ', crap(144), '\r\n'));
   r = ftp_recv_line(socket:soc);
  }

  for(j=0;j<num_dirs;j=j+1)
  {
   send(socket:soc, data: strcat('RMD ', crap(144),  '\r\n'));
   r = ftp_recv_line(socket:soc);
   if(!egrep(pattern:"^250 ", string:r))exit(0);
   send(socket:soc, data: 'CWD ..\r\n');
   r = ftp_recv_line(socket:soc);
  }
 }
}


# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
  num_dirs = 0;
  # We are in

  c = strcat('CWD ', wri, '\r\n');
  send(socket:soc, data:c);
  b = ftp_recv_line(socket:soc);
  cwd = strcat('CWD ', crap(144), '\r\n');
  mkd = strcat('MKD ', crap(144), '\r\n');
  pwd = 'PWD \r\n';

  #
  # Repeat the same operation 20 times. After the 20th, we
  # assume that the server is immune.
  #


  for(i=0;i<20;i=i+1)
  {
  send(socket:soc, data:mkd);
  b = ftp_recv_line(socket:soc);

  # No answer = the server has closed the connection.
  # The server should not crash after a MKD command
  # but who knows ?

  if(!b){
  	#security_hole(port);
	clean_exit();
	}

  if(!egrep(pattern:'^257 ', string:b))
  {
   i = 20;
  }
  else
  {
  send(socket:soc,data:cwd);
  b = ftp_recv_line(socket:soc);

  #
  # See above. The server is unlikely to crash
  # here

  if(!b)
       {
  	#security_hole(port);
	clean_exit();
       }

   if(!egrep(pattern:'^250 ', string:b))
   {
    i = 20;
   }
   else num_dirs = num_dirs + 1;
   }
  }

  #
  #If vulnerable, it will crash here
  #
  send(socket:soc,data:pwd);
  b = ftp_recv_line(socket:soc, retry: 3);
  if(!b)
       {
  	security_hole(port);
	clean_exit();
       }

  ftp_close(socket:soc);
 }
}

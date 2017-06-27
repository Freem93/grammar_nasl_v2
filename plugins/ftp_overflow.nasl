#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if(description)
{
 script_id(10084);
 script_version ("$Revision: 1.82 $");

 script_cve_id(
  "CVE-1999-0219",
  "CVE-2000-0870",
  "CVE-2000-0943",
  "CVE-2000-1035",
  "CVE-2000-1194",
  "CVE-2002-0126",
  "CVE-2003-0271",
  "CVE-2005-0634",
  "CVE-2005-1415"
 );
 script_bugtraq_id(269, 1227, 1675, 1690, 1858, 3884, 7251, 7278, 7307, 12704, 13454);
 script_osvdb_id(
  74,
  957,
  1555,
  1620,
  6800,
  11326,
  12077,
  12324,
  14369,
  16049
 );

 script_name(english:"Multiple FTP Server Command Handling Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is susceptible to buffer overflow attacks." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server closes the connection when a command or argument
is too long.  This is probably due to a buffer overflow and may allow
an attacker to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade / switch the FTP server software or disable the service if 
it is not needed." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'GlobalSCAPE Secure FTP Server Input Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1997/07/01");
 script_cvs_date("$Date: 2016/05/05 16:01:16 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 summary["english"] = "attempts some buffer overflows";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/login", "ftp/password");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_ftp_port(default: 21);

foreach f (make_list("msftpd", "ncftpd", "fw1ftpd", "vxftpd"))
  if (get_kb_item("ftp/"+port+"/"+f))
    exit(0, "The FTP server on port "+port+" is "+f+".");

function is_vulnerable (value)
{
 if (service_is_dead(port: port) > 0)
 {
   set_kb_item(name:"ftp/overflow", value:TRUE);
   set_kb_item(name:"ftp/"+port+"/overflow", value:TRUE);
   set_kb_item(name:"ftp/"+port+"/overflow_method", value:value);
   security_hole(port);
 }
 exit (0);
}

soc = open_sock_tcp(port);
if (! soc) exit(1, "Connection failed to port "+port+".");

  d = ftp_recv_line(socket:soc);
  if(!d){
	close(soc);
	exit(1, "No answer on port "+port+".");
	}
  if(!egrep(pattern:"^220[ -]", string:d))
   {
    # not an FTP server
    close(soc);
    exit(1, "The service on port "+port+" does not look like FTP.");	
   }
 
  if ("Microsoft FTP Service" >< d)
    exit(0, "MS FTP is running on port "+port+".");
 
  req = 'USER ftp\r\n';
  send(socket:soc, data:req);
  d = ftp_recv_line(socket:soc);
  ftp_close(socket:soc);
  if(!d)
  {
   exit(1, "No answer on port "+port+".");	
  }
  
  soc = open_sock_tcp(port);
  if ( ! soc ) exit(1, "Connection failed to port "+port+".");
  d = ftp_recv_line(socket:soc);
  s = strcat('USER ', crap(4096), '\r\n');
  send(socket:soc, data:s);
  d = ftp_recv_line(socket:soc);
  if(!d){
	close (soc);
	is_vulnerable (value:"USER");
	}

   # Let's try to access it with valid credentials now.
   login = get_kb_item("ftp/login");
   password = get_kb_item("ftp/password");

   s = strcat('USER ', login, '\r\n');
   send(socket:soc, data:s);
   d = ftp_recv_line(socket:soc);
   # ProFTPD 1.5.2 crashes with more than 12 KB
   s = strcat('PASS ', crap(12500), '\r\n');
   send(socket:soc, data:s);
   d = ftp_recv_line(socket:soc);
   if(!d){
	close (soc);
	is_vulnerable (value:"PASS");
	}

     s = strcat('PASS ', password, '\r\n');
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d) exit(1, "No answer from port "+port+".");

     foreach cmd (make_list ('CWD', 'LIST', 'STOR', 'RNTO', 'MKD', 'XMKD', 
     	 'RMD', 'XRMD', 'APPE', 'SIZE', 'RNFR', 'HELP', ''))
     {
       s = strcat(cmd, ' ', crap(4096), '\r\n');
       d = ftp_recv_line(socket:soc);
       if (! d)
       {
	close (soc);
	is_vulnerable (value: cmd);
       }
     }
		

   if ( soc )  close(soc);
 

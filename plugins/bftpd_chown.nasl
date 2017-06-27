#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10579);
 script_bugtraq_id(2120);
 script_osvdb_id(477, 1620);
 script_version ("$Revision: 1.36 $");
 script_cve_id("CVE-2001-0065", "CVE-2000-0943");
 
 script_name(english:"bftpd Multiple Command Remote Overflow");
 script_summary(english:"Checks if the remote bftpd daemon is vulnerable to a buffer overflow");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a remote buffer overflow vulnerability."
 );
 script_set_attribute(attribute:"description", value:
"The version of bftpd running on the remote host is vulnerable to a
remote buffer overflow attack when issued very long arguments to the
SITE CHOWN command.  A remote attacker could exploit this issue to
crash the FTP server, or possibly execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2000/Dec/222"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to bftpd version 1.0.24 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/12/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/10/27");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
                  
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl", "ftp_writeable_directories.nasl", "ftp_kibuv_worm.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");

if (report_paranoia < 2)
 exit(0, "This script only runs in 'paranoid' mode.");

#
# The script code starts here : 
#

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

port = get_ftp_port(default: 21);

# Connect to the FTP server

if(safe_checks())login = 0;


if(login)
{
 soc = open_sock_tcp(port);
 if(!soc)exit(1, "Cannot connect to TCP port "+port+".");
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
  req = string("SITE CHOWN AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA A");
  req = req + string("\r\n");
  send(socket:soc, data:req);
  r = ftp_recv_line(socket:soc);
  send(socket:soc, data:string("HELP\r\n"));
  r = ftp_recv_line(socket:soc, retry: 2);
  if(!r)security_hole(port);
  exit(0);
  }
   else {
    	ftp_close(socket: soc);
	}
}
 
banner = get_ftp_banner(port: port);
if(!banner)exit(1, "No FTP banner on port "+port+".");
  
if(egrep(pattern:"220.*bftpd 1\.0\.(([0-9][^0-9])|(1[0-3]))",
  	 string:banner)){
	 data = string(
	   "\n",
	   "Note that Nessus detected this issue solely based on the server banner\n"
	 );
	 security_hole(port:port, extra:data);
	 }


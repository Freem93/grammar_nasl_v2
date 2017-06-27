#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15851);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2001-0770");
 script_bugtraq_id(2782);
 script_osvdb_id(5540);

 script_name(english:"GuildFTPd Long SITE Command Overflow");
 script_summary(english:"Sends an oversized SITE command to the remote server");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is vulnerable to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote ftp server seems to be vulnerable to a denial of service
attack through the SITE command when handling specially long requests. 
An attacker can exploit this flaw in order to crash the affected
service or possibly execute arbitrary code." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/May/250" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/05/27");
 script_cvs_date("$Date: 2016/10/10 15:57:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_DENIAL);
  
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# da code
#

include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

login = get_kb_item_or_exit("ftp/login");
password = get_kb_item("ftp/password");

port = get_ftp_port(default: 21);

 banner = get_ftp_banner(port:port);
 if ( ! banner || "GuildFTP" >!< banner ) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(1);

  if(ftp_authenticate(socket:soc, user:login,pass:password))
  {
   data = strcat('SITE ', crap(262), '\r\n');
   send(socket:soc, data:data);
   reply = ftp_recv_line(socket:soc);
   sleep(1);
   if (service_is_dead(port: port) > 0)
     security_hole(port);
  }
ftp_close(socket: soc);

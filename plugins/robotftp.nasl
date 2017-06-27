#
# This script was written by Audun Larsen <larsen@xqus.com>
#

# Changes by Tenable:
# - use get_ftp_banner() and be solely banner-based [RD]
# - revised plugin title, added OSVDB ref, changed family (6/25/09)

include("compat.inc");

if(description)
{
 script_id(12082);
 script_version("$Revision: 1.11 $");
 script_bugtraq_id(9729);
 script_osvdb_id(55323);

 script_name(english:"Robo-FTP Pre-authentication Command Execution DoS");

 script_set_attribute(
  attribute:"synopsis",
  value:"The remote FTP server has a denial of service vulnerability."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host seems to be running Robo-FTP.

According to its banner, this version has a denial of service
vulnerability.  Sending certain commands to the service before
authentication has been negotiated causes the service to crash."
 );
 script_set_attribute(
  attribute:"see_also",
  value:"http://securityvulns.ru/files/robo.c"
 );
 script_set_attribute(
  attribute:"solution",
  value:"Upgrade to the latest version of this application."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/27");
 script_cvs_date("$Date: 2011/03/11 20:33:10 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Checks for version of RobotFTP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Audun Larsen");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_ftp_port(default: 21);
banner  = get_ftp_banner(port:port);
if ( ! banner ) exit(1);

 if ( egrep(pattern:"^220.*RobotFTP", string:banner) )
 {
  security_warning(port);
  exit(0);
 }

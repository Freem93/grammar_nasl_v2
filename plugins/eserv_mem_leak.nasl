#
# (C) Tenable Network Security, Inc.
#

# From: "Matthew Murphy" <mattmurphy@kc.rr.com>
# To: "BugTraq" <bugtraq@securityfocus.com>,
# Date: Sun, 11 May 2003 11:21:43 -0500
# Subject: [VulnWatch] eServ Memory Leak Enables Denial of Service Attacks


include("compat.inc");


if(description)
{
 script_id(11619);
 script_version ("$Revision: 1.16 $");
 script_osvdb_id(12080);

 script_name(english:"Eserv Non-Terminated Connection Saturation DoS");
 script_summary(english:"Determines if the remote host is running Eserv");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote server has a denial of service vulnerability."
 );
 script_set_attribute(attribute:"description", value:
"The remote host is running Eserv HTTP/SMTP/FTP server.

According to its version number, there is a memory leak in this
software which allows any attacker to consume all the available
memory on this host by making repeated requests to this service."
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/vulnwatch/2003/q2/66"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"There is no known solution at this time."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/11");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "ftpserver_detect_type_nd_version.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/www", "Services/smtp", "Services/ftp", 21, 25, 80);

 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("ftp_func.inc");
include("smtp_func.inc");

port = get_http_port(default:80, dont_exit: 1);

if (port && get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(banner)
 {
  if(egrep(pattern:"^Server:.*Eserv/[0-2]", string:banner))
  {
   security_hole(port);
  }
 }
}

port = get_service(svc: "smtp", default: 25, exit_on_fail: 0);
if(get_port_state(port))
{
 banner = get_smtp_banner(port:port);
 if(banner)
 {
  if(egrep(pattern:"^220*Eserv/[0-2]", string:banner))
  {
   security_hole(port);
  }
 }
}

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (! banner) exit(1);

if(egrep(pattern:"^220*Eserv/[0-2]", string:banner))
  {
   security_hole(port);
  }


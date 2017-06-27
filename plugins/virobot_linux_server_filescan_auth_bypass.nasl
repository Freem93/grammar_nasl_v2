#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20968);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2006-0864");
  script_bugtraq_id(16768);
  script_osvdb_id(23401);

  script_name(english:"ViRobot Linux Server filescan Authentication Bypass");
  script_summary(english:"Checks for authentication bypass vulnerability in ViRobot Linux Server's filescan component");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an authentication bypass flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ViRobot Linux Server, a commercial
antivirus application server. 

The installed version of ViRobot Linux Server has a flaw such that an
attacker can bypass authentication and gain access to its 'filescan'
component by supplying a special cookie.  An unauthenticated attacker
may be able to leverage this flaw to delete arbitrary files on the
remote host or disable access to the service by submitting scans of a
large number of large files on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/425788/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa2f7f08" );
 script_set_attribute(attribute:"solution", value:
"Apply the vendor patch referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/22");
 script_cvs_date("$Date: 2011/12/05 21:49:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);

# Try to exploit the flaw.
set_http_cookie(name: "HTTP_COOKIE", value: "test");
r = http_send_recv3(method: "GET", item:string("/cgi-bin/filescan"), port:port);
if (isnull(r)) exit(0);

# There's a problem if we gained access.
if (
  "<title>ViRobot Linux Server" >< r[2] &&
  "<form name=dir_form method=post" >< r[2]
) {
  security_hole(port);
}

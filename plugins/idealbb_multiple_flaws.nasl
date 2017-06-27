#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15541);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2004-2207", "CVE-2004-2208", "CVE-2004-2209");
  script_bugtraq_id(11424);
  script_osvdb_id(10760, 10761, 10762);

  script_name(english:"IdealBB Multiple Vulnerabilities (XSS, SQLi, more)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting an ASP application that is affected
by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IdealBB, a web-based bulletin board 
written in ASP.

The remote version of this software has multiple flaws - SQL
injection, cross-site scripting and HTTP response splitting
vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"http://archive.cert.uni-stuttgart.de/bugtraq/2006/05/msg00135.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/11");

 script_cvs_date("$Date: 2015/02/03 17:40:02 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:ideal_science:idealbb");
script_end_attributes();


  script_summary(english:"Checks IdealBB version");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  script_require_keys("www/ASP");
  exit(0);
}

# the code!

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!get_port_state(port)) exit(0);
if(!can_host_asp(port:port))exit(0);

function check(req)
{
  local_var buf, r;
  buf = http_get(item:string(req,"/idealbb/default.asp"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<title>The Ideal Bulletin Board</title>.*Ideal BB Version: 0\.1\.([0-4][^0-9]|5[^.]|5\.[1-3][^0-9])", string:r))
  {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
  }
}

foreach dir (cgi_dirs())
    check(req:dir);
exit(0);

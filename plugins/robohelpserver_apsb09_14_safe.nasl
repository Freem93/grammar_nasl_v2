#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41946);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/09 20:54:57 $");

  script_cve_id("CVE-2009-3068");
  script_bugtraq_id(36245);
  script_osvdb_id(57896);
  script_xref(name:"Secunia", value:"36467");

  script_name(english:"Adobe RoboHelp Server Security Bypass (APSA09-05)");
  script_summary(english:"Looks at the HTTP status code of a bad request");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has a security bypass
vulnerability that can lead to arbitrary command execution.");
  script_set_attribute(attribute:"description", value:
"The version of RoboHelp Server running on the remote host has a
security bypass vulnerability.  Arbitrary files can be uploaded to
the web server by using a specially crafted POST request.  Uploading
a JSP file can result in command execution as SYSTEM.

Since safe checks are enabled, Nessus detected this vulnerability
solely by issuing an incomplete POST request and checking the
resulting HTTP status code.");
  # http://web.archive.org/web/20091024040825/http://www.intevydis.com/blog/?p=69
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f4448043");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-066/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2009/Sep/359");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa09-05.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb09-14.html");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in Adobe's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Adobe Robohelp Server 8 Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe RoboHelp Server 8 Arbitrary File Upload and Execute');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:robohelp_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:8080);
  
# Make sure the web page exists before making a POST request
page = '/robohelp/server?';
query = 'area=' + SCRIPT_NAME;
url = page + query;
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

# If we're not redirected to a project or a welcome screen, this probably isn't
# Adobe RoboHelp. If any projects have been published, we should see our query
# string in the redirect.  If no projects have been published, we should see a
# redirect to a welcome page
pattern = string(
  'http-equiv="refresh" content="0;url=(',
  'http://[^/]+',
  ereg_replace(string:page, pattern:"\?", replace:"\?"), urlencode(str:query),
  '|',
  '/robohelp/robo//server/resource/mr_sys_welcome.htm)'
);
if (!egrep(pattern:pattern, string:tolower(res[2])) )
  exit(0, "RoboHelp doesn't appear to be available via port "+port+".");

# Since we're not providing any POST data, a file won't be created, but we'll
# be able to tell if the system is patched based on the HTTP return code
url = '/robohelp/server?PUBLISH=1';
headers = make_array("UID", rand());
res = http_send_recv3(
  method:"POST",
  item:url,
  port:port,
  exit_on_fail: 1,
  add_headers:headers
);

headers = parse_http_headers(status_line:res[0], headers:res[1]);
http_code = headers['$code'];
if (isnull(http_code)) exit(1, "Error parsing HTTP response code");

# If we get an HTTP OK, it's vulnerable.  If our request required authentication# it's patched
if (http_code == 200) security_hole(port);
else if (http_code == 401) exit(0, "The web server on port "+port+" is not affected");
else exit(1, "Unexpected HTTP status code on port "+port);

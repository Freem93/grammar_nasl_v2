#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64245);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_cve_id("CVE-2012-5469");
  script_bugtraq_id(56920);
  script_osvdb_id(88391);
  script_xref(name:"EDB-ID", value:"23356");

  script_name(english:"Portable phpMyAdmin Plugin for WordPress 'wp-pma-mod' Authentication Bypass");
  script_summary(english:"Attempts to access Portable phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Portable phpMyAdmin Plugin for WordPress installed on the remote
host is affected by an authentication bypass vulnerability because the
/wp-pma-mod/ path fails to properly authorize users. his may allow an
attacker to bypass access restrictions and gain access to the
administrative console to perform unauthorized actions.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Dec/91");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/extend/plugins/portable-phpmyadmin/changelog/");

  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = 'Portable phpMyAdmin';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "portable-phpmyadmin/wp-pma-mod/js/navigation.js"][0] =
    make_list('function PMA_save');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed)
audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# Attempt to access phpMyAdmin
exploit = "/wp-content/plugins/portable-phpmyadmin/wp-pma-mod/";
res = http_send_recv3(
    method    : "GET",
    item      : dir + exploit,
    port         : port,
    exit_on_fail : TRUE
);

if (
  "<title>phpMyAdmin" >< res[2] &&
  "<p>phpMyAdmin is more friendly" >< res[2]
)
{
  out = strstr(res[2], "<title");
  count = 0;
  # Format our output for reporting. Limit to 20 lines
  foreach line (split(out))
  {
    output += line;
    count++;
    if (count >= 20) break;
  }

  if (report_verbosity > 0)
  {
    snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    report =
      '\nNessus was able to verify the issue using the following request :' +
      '\n' +
      '\n' + install_url + exploit +
      '\n';
      if (report_verbosity > 1)
      {
        report +=
          '\nThis produced the following truncated output : ' +
          '\n' + snip +
          '\n' + output + snip +
          '\n';
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " Plugin");

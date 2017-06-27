#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76071);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/19 18:10:51 $");

  script_cve_id("CVE-2014-3961");
  script_bugtraq_id(67769);
  script_osvdb_id(107626);
  script_xref(name:"EDB-ID", value:"33613");

  script_name(english:"Participants Database Plugin for WordPress < 1.5.4.9 'query' Parameter SQL Injection");
  script_summary(english:"Checks the plugin version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Participants Database Plugin for WordPress installed on the remote
host is prior to version 1.5.4.9. It is, therefore, affected by a SQL
injection vulnerability due to failure to properly sanitize
user-supplied input to the 'query' parameter in the 'pdb-signup'
script. A remote, unauthenticated attacker could leverage this issue
to execute arbitrary SQL statements against the backend database,
leading to manipulation of data or the disclosure of arbitrary data.

The application is reportedly also affected by an unspecified flaw in
which insufficient privilege checks allows an unauthenticated user to
execute actions reserved for administrative users when shortcodes are
used.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Jun/0");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/plugins/participants-database/changelog");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.5.4.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:xnau:participants_databas3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

plugin = "Participants Database";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list("function serializeList", "#confirmation-dialog'");
  checks["/wp-content/plugins/participants-database/js/manage_fields.js"] = regexes;

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

version = UNKNOWN_VER;

# Get version from readme.txt
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "/wp-content/plugins/participants-database/readme.txt",
  exit_on_fail : TRUE
);

if ("=== Participants Database ===" >< res[2] && "Stable tag:" >< res[2])
{
  match = NULL;
  # Check Changelog section as Stable tag does not appear to be updated often
  output = strstr(res[2], "== Changelog ==");
  if (!isnull(output))
  {
    match = eregmatch(pattern:"= ([0-9\.]+) =", string:output);
    if (!isnull(match)) version = match[1];
  }
  # Fall back to Stable Tag as a backup
  else
  {
    pattern = "Stable tag: ([0-9\.]+)";
    match = eregmatch(pattern:pattern, string:res[2]);
  }
  if (isnull(match)) exit(1, "Failed to read the 'readme.txt' file for the WordPress " + plugin + " located at " + install_url + ".");
  version = match[1];


  fix = "1.5.4.9";
  if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
  {
    set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
    if (report_verbosity > 0)
    {
      report =
        '\n  URL               : ' +install_url+
        '\n  Installed version : ' +version+
        '\n  Fixed version     : ' +fix + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin", version);

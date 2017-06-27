#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64991);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_osvdb_id(88744);

  script_name(english:"W3 Total Cache Plugin for WordPress Cache File Direct Request Information Disclosure");
  script_summary(english:"Looks for W3 dbcache directory listing.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The W3 Total Cache Plugin for WordPress installed on the remote host
is affected by an information disclosure vulnerability because it
stores cache files in a publicly accessible directory. If directory
browsing is enabled on a web server, an attacker can browse to
/wp-content/w3tc/dbcache and access the database cache files.

The database cache files can store information such as usernames and
passwords and can disclose additional sensitive information. If
directory browsing is not enabled, an attacker can still attempt to
brute-force the names of the directories and files to view cached
database queries and results.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Dec/242");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/extend/plugins/w3-total-cache/changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 0.9.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'W3-Total-Cache Wordpress-plugin 0.9.2.4 (or before) Username and Hash Extract');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
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

plugin = "W3 Total Cache";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  # versions < 0.9.2.4 had js in /inc but starting with 0.9.2.4 and up, /js
  # can be found in /pub
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "w3-total-cache/pub/js/options.js"][0] =
    make_list('function w3tc_');

  checks[path + "w3-total-cache/inc/js/options.js"][0] =
    make_list('function w3tc_');

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

vuln = FALSE;
url = "/wp-content/w3tc/dbcache/";

res2 = http_send_recv3(
  method       : "GET",
  item         : dir + url,
  port         : port,
  exit_on_fail : TRUE
);

# Check for a directory listing
if (
  egrep(pattern:"<h1>Index of (.+)?/wp-content/w3tc/dbcache</h1>",string:res2[2]) &&
  ">Parent Directory<" >< res2[2]
)
{
  # Vulnerable versions had directory names with 1 character/number
  pat = egrep(pattern:'<a href="([a-zA-Z0-9]{1})/">', string:res2[2]);

  if (pat || old_ver)
  {
    vuln = TRUE;
    msg = 'verify that the issue exists by examining the' +
     '\noutput from the following URL :';
  }
}
else if (old_ver)
{
  vuln = TRUE;
  msg = 'determine that a vulnerable version of the plugin is' +
    '\ninstalled on the remote host, however directory browsing does not' +
    '\nappear to be enabled. This can be verified with the following URL :';
}

if (!vuln && !old_ver)
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");

if (report_verbosity > 0)
{
  report =
    '\nNessus was able to '+ msg +
    '\n' +
    '\n' + install_url + url +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);

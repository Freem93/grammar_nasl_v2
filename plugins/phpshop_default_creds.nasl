#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(43158);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_name(english:"phpShop Default Credentials");
  script_summary(english:"Tries to login using default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(
    attribute:"description",
    value:
"It is possible to log into the remote phpShop installation by providing
default credentials.  Several accounts are included in the default
phpShop installation.  A remote attacker could exploit this to gain
unauthorized, potentially administrative control of the phpShop
installation."
  );
  script_set_attribute(attribute:"solution", value:"Delete unused accounts, and secure others with strong passwords.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:phpshop:phpshop");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 80);
  script_dependencies("phpshop_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/phpshop");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'phpshop', port:port, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

url = install['dir'] + '/index.php?login=1';
headers = make_array('Content-Type', 'application/x-www-form-urlencoded');


function login()
{
  local_var user, pass, res, res_hdrs, postdata, logged_in;
  user = _FCT_ANON_ARGS[0];
  pass = _FCT_ANON_ARGS[1];
  logged_in = FALSE;

  clear_cookiejar();

  postdata = 'func=userLogin&username='+user+'&password='+pass;
  res = http_send_recv3(
    method:'POST',
    item:url,
    data:postdata,
    add_headers:headers,
    port:port,
    exit_on_fail:TRUE
  );
  if ('<td align="right">Logged in as ' >< res[2]) logged_in = TRUE;

  return logged_in;
}

accounts = make_array(
  'admin', 'test',
  'storeadmin', 'test',
  'test', 'test',
  'demo', 'demo',
  'gold', 'test'
);

success = make_list();

# Try to login as all default accounts. If the "Perform thorough tests" setting is not enabled,
# stop on the first successful login
foreach user (sort(keys(accounts)))
{
  pass = accounts[user];

  if (login(user, pass)) success = make_list(success, user);
  if (max_index(success) > 0 && !thorough_tests) break;
}

full_url = build_url(qs:url, port:port);

if (max_index(success) > 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to login using the following information :\n\n' +
      'URL      : '+full_url+'\n';

    foreach user (success)
      report += 'Login credentials : '+user+' / '+accounts[user]+'\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "phpShop", full_url);


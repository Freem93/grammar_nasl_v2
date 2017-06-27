#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(43352);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/12/08 15:38:46 $");

  script_osvdb_id(61131);

  script_name(english:"Oracle WebLogic Default Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(
    attribute:"description",
    value:
"It is possible to log into the remote WebLogic installation by
providing the default credentials.  A remote attacker could exploit this
to gain administrative control of this installation."
  );
  script_set_attribute(attribute:"solution", value:"Secure any default accounts with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 7001);
  script_dependencies("weblogic_detect.nasl");
  script_require_keys("www/weblogic");
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# globals
appname = "WebLogic";
get_kb_item_or_exit("www/weblogic");
port = get_http_port(default:7001);
get_kb_item_or_exit("www/weblogic/" + port + "/installed");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

url = '/console';
full_url = build_url(qs:url, port:port);

accounts = make_array(
  'weblogic', 'weblogic',
  'system', 'password'
);


# tries to login with the given username (arg1) and password (arg2)
function login()
{
  local_var user, pass, res, res_hdrs, postdata, logged_in;
  user = _FCT_ANON_ARGS[0];
  pass = _FCT_ANON_ARGS[1];
  logged_in = FALSE;

  postdata = 'j_username='+user+'&j_password='+pass;
  res = http_send_recv3(
    method:'POST',
    item:url+'/j_security_check',
    data:postdata,
    content_type:'application/x-www-form-urlencoded',
    port:port,
    exit_on_fail:TRUE
  );
  if ('Authentication Denied' >< res[2]) return FALSE;

  # A successful login will result in three redirects.  This will only check
  # for the first
  res_hdrs = parse_http_headers(status_line:res[0], headers:res[1]);

  if (
    !isnull(res_hdrs) &&
    ereg(string:res_hdrs['location'], pattern:url+'/index.jsp$')
  ) logged_in = TRUE;

  return logged_in;
}


#
# script begins here
#

success = make_list();

res = http_send_recv3(method:"GET", item:url, port:port, follow_redirect:2, exit_on_fail:TRUE);

if (
  '<TITLE>BEA WebLogic Server Administration Console</TITLE>' >!< res[2] &&
  '<title>Oracle WebLogic Server Administration Console</title>' >!< res[2] &&
  '<TITLE>WebLogic Server' >!< res[2]
)
{
  audit(AUDIT_INST_VER_NOT_VULN, appname);
}

foreach user (accounts)
{
  pass = accounts[user];
  if (login(user, pass))
  {
    success = make_list(success, user);
    if (!thorough_tests) break;
  }
}

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
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, full_url);

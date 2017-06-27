#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78769);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/17 21:12:12 $");

  script_name(english:"Cisco UCS Director Default Credentials (Web UI)");
  script_summary(english:"Tries to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into the remote Cisco UCS Director installation
by providing the default credentials. A remote, unauthenticated
attacker can exploit this to gain administrative control.");
  script_set_attribute(attribute:"solution", value:"Secure any default accounts with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:ucs_director");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ucs_director_webui_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("Host/Cisco/UCSDirector/WebUIVersion");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Check to see if WebUI was detected
get_kb_item_or_exit("Host/Cisco/UCSDirector/WebUIVersion");

port = get_http_port(default:80);

url = '/app/ui';
full_url = build_url(qs:url, port:port);

accounts = make_array(
  "admin", "admin"
);

# tries to login with the given username (arg1) and password (arg2)
function login()
{
  local_var user, pass, res, res_hdrs, postdata, logged_in;
  user = _FCT_ANON_ARGS[0];
  pass = _FCT_ANON_ARGS[1];
  logged_in = FALSE;

  clear_cookiejar();
  init_cookiejar();

  res = http_send_recv3(method:"GET", item:url+'/login.jsp', port:port);

  postdata = 'Submit=Login&operation=Login&'+'username='+user+'&password='+pass;
  res = http_send_recv3(
    method:'POST',
    item:url+'/LoginServlet',
    data:postdata,
    content_type:'application/x-www-form-urlencoded',
    port:port
  );

  # Notes:
  # A successful login will result in a redirect. The interface is flash
  # based so it's hard to verify success with HTTP requests since all the
  # resources (js/jsp/swf) can be accessed without auth.
  res_hdrs = parse_http_headers(status_line:res[0], headers:res[1]);

  if (
    !isnull(res_hdrs) &&
    ereg(string:res_hdrs['location'], pattern:'app/cloudmgr/cloudmgr.jsp$')
  ) logged_in = TRUE;

  return logged_in;
}

success = make_list();

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
      '\n' + 'Nessus was able to login using the following credentials:' +
      '\n' + '  URL      : '+full_url;
    foreach user (success)
    {
      report +=
      '\n' + '  Username : '+user +
      '\n' + '  Password : '+accounts[user];
    }
    report += '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Cisco UCS Director", full_url);

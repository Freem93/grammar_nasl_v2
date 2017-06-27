#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28373);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_name(english:"Plumtree Portal Default Credentials");
  script_summary(english:"Tries to login to the portal with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web portal is protected with default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Plumtree portal, a corporate web portal. 

The remote installation of the Plumtree portal is configured to use
default credentials to control administrative access.  Knowing these, an
attacker can gain control of the affected application.");
  script_set_attribute(attribute:"solution", value:"Assign a password to the 'Administrator' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user = "Administrator";
pass = "";


init_cookiejar();
# Make sure the cookie does not already exist in the default jar
if (get_http_cookie(name: "plloginoccured") == "true")
  erase_http_cookie(name: "plloginoccured");

# Loop through directories.
dirs = list_uniq("/portal", cgi_dirs());
vuln = FALSE;
found = FALSE;

foreach dir (dirs)
{
  # Check whether the login script exists.
  url = dir + "/server.pt?";
  r = http_send_recv3(method: "GET", item:url, port:port, exit_on_fail:TRUE);

  # If it does...
  if ('PTIncluder.' >< r[2] && "!--Portal Version: " >< r[2])
  {
    found = TRUE;
    install_url = build_url(qs:url, port:port);
    # Try to log in.
    postdata =
      "in_hi_space=Login&" +
      "in_hi_spaceID=2&" +
      "in_hi_control=Login&" +
      "in_hi_dologin=true&" +
      "in_tx_username=" + user + "&" +
      "in_pw_userpass=" + pass + "&" +
      "in_se_authsource=";

    r = http_send_recv3(method: "POST", item: url, data: postdata,port: port,
add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"), exit_on_fail: TRUE);

    # There's a problem if...
    if (
      # we got in...
      get_http_cookie(name: "plloginoccured") == "true" &&
      # as Administrator
      "in_hi_userid=1" >< r[1]+r[2]
    )
    {
      vuln = TRUE;
      break;
    }
  }
}
if (!found)
  audit(AUDIT_WEB_APP_NOT_INST, "Plumtree Portal", port);

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to gain access using the following information :\n' +
      '\n' +
      '  URL      : ' + install_url +
      '  User     : ' + user + '\n' +
      '  Password : ' + pass + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Plumtree Portal", install_url);

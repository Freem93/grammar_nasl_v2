#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70211);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_name(english:"Alcatel OmniSwitch Default Credentials (http)");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(
    attribute:"description",
    value:
"It is possible to log into the remote Alcatel Switch by providing the
default credentials.  A remote attacker could exploit this to gain
administrative control of this installation."
  );
  script_set_attribute(attribute:"solution", value:"Secure any default accounts with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:alcatel-lucent:omniswitch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alcatel:aos");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 7001);
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# globals
port = get_http_port(default:80);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


init_cookiejar();

res = http_get_cache(item:"/", port:port);
if ("/web/content/index.html" >!< res ) audit(AUDIT_HOST_NOT, "Alcatel Switch");

res = http_send_recv3(method:"GET", item:"/web/content/login.html", port:port, exit_on_fail:TRUE);
if ('<frame name="gral_toolbar" target="main" src="/web/content/gral_toolbar.html' >< res[2]) audit(AUDIT_RESP_BAD, port);

res = http_send_recv3(method:"POST", item:"/web/content/login.html", port:port, data:"userName=admin&password=switch&B1=Login", add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded"), exit_on_fail:TRUE);

if ('<frame name="gral_toolbar" target="main" src="/web/content/gral_toolbar.html' >< res[2])
{
  security_hole(port:port, extra:"It was possible to log in as admin/switch");
  res = http_send_recv3(method:"GET", item:"/web/content/webview_logout.html", port:port);
}
else exit(0, "The remote switch does not have the default credentials set.");

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90407);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_osvdb_id(136488);

  script_name(english:"Open Source Point Of Sale Default Credentials");
  script_summary(english:"Attempts to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is protected using
default credentials.");
  script_set_attribute(attribute:"description", value:
"The Open Source Point of Sale (POS) application running on the remote
web server uses default credentials for the administrator account. An
attacker can exploit this to gain administrative access to the
application.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/jekkos/opensourcepos");
  script_set_attribute(attribute:"solution", value:
"Change the password for the 'admin' user.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:open_source_point_of_sale_project:open_source_point_of_sale");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("open_source_pos_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/Open Source Point of Sale");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Open Source Point of Sale";

get_install_count(app_name:app, exit_if_zero:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

info = "";
url = dir + '/index.php/login';

user = "admin";
pass = "pointofsale";

postdata = "username="+user+"&password="+pass+"&loginButton=Go";

res = http_send_recv3(
  port     : port,
  method   : "POST",
  item     : url,
  data     : postdata,
  content_type : "application/x-www-form-urlencoded",
  exit_on_fail : TRUE,
  follow_redirect : 2
);
# There's a problem if we've bypassed authentication.
if (
  'id="menubar"' >< res[2] &&
  '>Store Config<' >< res[2] &&
  '>Logout<' >< res[2]
)
{
  info +=
    '\n  Username : ' + user +
    '\n  Password : ' + pass + '\n';
}

if (info)
{
  report = '\n' + 'Nessus was able to gain access using the following URL :' +
           '\n' +
           '\n' + '  ' + build_url(port:port, qs:url) +
           '\n' +
           '\n' + 'and the following set of credentials :\n' +
           info;
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(port:port, qs:dir));

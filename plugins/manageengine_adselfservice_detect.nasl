#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56509);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/15 17:51:38 $");

  script_name(english:"ManageEngine ADSelfService Plus Detection");
  script_summary(english:"Checks for evidence of ManageEngine ADSelfService.");

  script_set_attribute(attribute:"synopsis", value:
"A help desk management application is running on the remote web
server.");
  script_set_attribute(attribute:"description", value:
"ManageEngine ADSelfService Plus, a web-based self-service password
management application written in Java, is running on the remote web
server.");
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/products/self-service-password/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_adselfservice_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8888);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:8888);

installed = FALSE;
url = '/authorization.do';
appname = "ManageEngine ADSelfService Plus";

res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE, follow_redirect:1);
if (
  (
    # 4.0.x -4.4.x
    (
      (
        (
          "Forget Domain Password?" >< res[2] &&
          "Unlock Domain Account?"  >< res[2]
        )
        ||
        'var loginTxt = new Array("Domain User Login", "Self-Service Admin Login");' >< res[2]
      )
      &&
      egrep(pattern:'name="domainName" value="ADSelfService (Plus )?Authentication"', string:res[2])
    )
    ||
    # 4.5.x - build 5314
    (
      (
        'var jsTitleMsg=eval(({adssp_reset_unlock_accounts_username_' >< res[2] ||
        'var jsTitleMsg=eval(({adssp_reports_common_text_filter' >< res[2] ||
        'document.getElementById("domainLogin").src = \'authorization.do\';' >< res[2]
      )
      &&
      'link REL="SHORTCUT ICON" HREF="images/adssp_favicon.ico"' >< res[2]
    )
  )
  &&
  # Common to all
  egrep(pattern:'<body.*onload="(createSearch\\(\'AnonymousAccess\'\\);|javascript:getCookie\\(\\))', string:res[2]) &&
  egrep(pattern:'title>.*ManageEngine - ADSelfService', string:res[2])
)
{
  version = UNKNOWN_VER;

  # Save info about the install.
  register_install(
    app_name  : appname,
    port      : port,
    path      : "",
    version   : version,
    webapp    : TRUE
  );

  installed = TRUE;
}

if (installed){

    # Report findings.
  report = report_installs(
    app_name     : appname,
    port         : port
  );

}
else audit(AUDIT_NOT_DETECT, appname, port);

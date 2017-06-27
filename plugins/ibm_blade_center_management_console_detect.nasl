#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(68904);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/07/16 13:36:06 $");

  script_name(english:"IBM Blade Center Advanced Management Console Detection");
  script_summary(english:"Detects IBM Blade Center Advanced Management Console");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an IBM Blade Center management console.");
  script_set_attribute(attribute:"description", value:
"IBM Blade Center Advanced Management Console was detected on the remote
host.  This console allows administrators to remotely configure IBM
Blade Center servers.");
  script_set_attribute(attribute:"see_also", value:"http://www-03.ibm.com/systems/bladecenter/index.html");
  # http://publib.boulder.ibm.com/infocenter/bladectr/documentation/topic/com.ibm.bladecenter.advmgtmod.doc/kp1bb_pdf.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd789253");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:advanced_management_module");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 3466);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

login_page = '/shared/userlogin.php';
res = http_send_recv3(method:"GET", item:login_page, port:port, exit_on_fail:TRUE);
if (
  "IBM BladeCenter Advanced Management Module" >< res[2] &&
  "<title>Log In</title>" >< res[2]
)
{
  install = add_install(dir:'/', appname:'ibm_blade_center_console', port:port);

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:'IBM Blade Center Advanced Management Console',
      installs:install,
      item:login_page,
      port:port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_NOT_DETECT, "IBM Blade Center Advanced Management Console", port);

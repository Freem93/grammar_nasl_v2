#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62292);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/02/03 17:58:16 $");

  script_name(english:"SAP Host Control SOAP Web Service Detection");
  script_summary(english:"Looks for the SOAP endpoint");

  script_set_attribute(attribute:"synopsis", value:"The remote web server has a SOAP endpoint.");
  script_set_attribute(attribute:"description", value:
"SAP Host Control, a SOAP endpoint, is running on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://scn.sap.com/community/netweaver");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 1128, 1129);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

app = "SAP Host Control";

port = get_kb_item("Services/www");
if (isnull(port))
{
  port = 1128;
  if (!service_is_unknown(port:port, ipproto:"tcp"))
    exit(0, "The service on port " + port + " has been previously identified.");
}

if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# From an SAP document:
#
# The SAP Host Agent runs on port 1128 and therefore the WSDL of the
# SAP Host Agent can be fetched by executing:
#
#   http://<host>:1128/SAPHostControl/?wsdl
checks = make_nested_array(
  "/SAPHostControl/?wsdl", make_nested_list(
    make_nested_list(
      '<definitions *name *= *"SAPHostControl"',
      '<service *name *= *"SAPHostControl" *>'
    ),
    make_nested_list()
  )
);

installs = find_install(
  all         : FALSE,
  appname     : "sap_host_control",
  checks      : checks,
  dirs        : make_list(""),
  port        : port,
  method      : "GET"
);

if (isnull(installs)) audit(AUDIT_NOT_DETECT, app, port);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : app,
    installs     : installs,
    port         : port
  );
}

security_note(port:port, extra:report);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62291);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/06/05 15:04:35 $");

  script_name(english:"SAP Control SOAP Web Service Detection");
  script_summary(english:"Looks for the SOAP endpoint");

  script_set_attribute(attribute:"synopsis", value:"The remote web server has a SOAP endpoint.");
  script_set_attribute(attribute:"description", value:
"SAP Control, a SOAP endpoint, is running on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://scn.sap.com/community/netweaver");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 50013, 50014);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

function parse_get_version_info_response()
{
  local_var xml;
  xml = _FCT_ANON_ARGS[0];

  # Remove all newlines, in case the format changes to multi-line in
  # future.
  xml = str_replace(string:xml, find:'\n', replace:"");

  # Store all the version information in an array to be returned.
  local_var files;
  files = make_array();

  # Regexes for parsing.
  local_var re_item, re_name;
  re_item = "<item> *<Filename>([^<]*)</Filename> *<VersionInfo>([^<]*)</VersionInfo> *<Time>[^<]*</Time> *</item>";
  re_name = "^.*[\\/]([^\\/]+?)(?:\.exe|\.dll)?$";

  # Parse out each <item> tag, removing them as we go.
  while (TRUE)
  {
    local_var m;
    m = eregmatch(string:xml, pattern:re_item);
    if (isnull(m))
      break;
    xml = str_replace(string:xml, find:m[0], replace:"");

    local_var path, ver;
    path = m[1];
    ver = m[2];

    m = eregmatch(string:path, pattern:re_name);
    if (isnull(m))
      break;

    local_var name;
    name = m[1];

    files[name] = make_array("version", ver, "path", path);
  }

  return files;
}
app = "SAP Control";

port = get_kb_item("Services/www");
if (isnull(port))
{
  port = 50013;
  if (!service_is_unknown(port:port, ipproto:"tcp"))
    exit(0, "The service on port " + port + " has been previously identified.");
}
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

res = http_send_recv3(
  port         : port,
  method       : "GET",
  item         : "/sapmc/sapmc.html",
  exit_on_fail : TRUE
);

if (
  res[2] !~ "<title> *SAP *Management *Console *</title>" ||
  res[2] !~ "<applet[^>]*code *= *com.sap.managementconsole.applet.ManagementConsoleInstallerApplet.class"
) audit(AUDIT_NOT_LISTEN, app, port);

soap =
  '<?xml version="1.0" encoding="UTF-8"?>
   <SOAP-ENV:Envelope
     xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
     xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xmlns:xsd="http://www.w3.org/2001/XMLSchema"
     xmlns:SAPControl="urn:SAPControl"
     xmlns:SAPCCMS="urn:SAPCCMS"
     xmlns:SAPHostControl="urn:SAPHostControl"
     xmlns:SAPOscol="urn:SAPOscol"
     xmlns:SAPDSR="urn:SAPDSR">
     <SOAP-ENV:Body>
       <SAPControl:GetVersionInfo />
     </SOAP-ENV:Body>
   </SOAP-ENV:Envelope>';

hdrs = make_array("SOAPAction", '""');

res = http_send_recv3(
  port         : port,
  method       : "POST",
  item         : "/",
  add_headers  : hdrs,
  data         : soap
);

# The port may have closed between connections.
if (isnull(res))
  audit(AUDIT_NOT_LISTEN, "SAPControl", port);

if ("<SOAP-ENV:Envelope" >!< res[2])
  audit(AUDIT_RESP_BAD, port, "SOAP request", "TCP");

files = parse_get_version_info_response(res[2]);
if (isnull(files))
  audit(AUDIT_RESP_BAD, port, "SOAP request", "TCP");

# SAP can run multiple instances on a single host, differentiated by
# their instance number, a two-digit code used to determine what ports
# the instance's components will listen on.
#
# Anything outside of the normal range indicates port forwarding,
# which means we can't infer the instance number.
if (port >= 50013 || port <= 59913)
  inst = substr(string(port), 1, 2);
else
  inst = "unknown (port " + port + ")";
set_kb_item(name:"sap/instance", value:inst);

foreach name (keys(files))
{
  version = files[name]["version"];
  path = files[name]["path"];

  set_kb_item(name:"sap/" + inst + "/" + name +  "/path", value:path);
  set_kb_item(name:"sap/" + inst + "/" + name +  "/version", value:version);
}

control = files["sapstartsrv"];
control_version = UNKNOWN_VER;
if (!isnull(control))
  control_version = control["version"];

installs = add_install(
  installs : NULL,
  port     : port,
  appname  : "sap_control",
  dir      : "/",
  ver      : control_version
);

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

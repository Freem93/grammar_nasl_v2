#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62353);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/09/27 16:08:14 $");

  script_name(english:"OpenStack Keystone Detection");
  script_summary(english:"Looks for the OpenStack Keystone API.");

  script_set_attribute(attribute:"synopsis", value:
"An instance of OpenStack Keystone was found on the remote host.");
  script_set_attribute(attribute:"description", value:
"OpenStack Keystone, a Python application that provides identity, token,
catalog and policy services to other OpenStack components was found on
the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.net/keystone");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openstack:keystone");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 5000, 35357);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("json.inc");
include("misc_func.inc");
include("path.inc");
include("webapp_func.inc");

app = "OpenStack Keystone";

# Get the ports that webservers have been found on.
port = get_kb_item("Services/www");
if (isnull(port))
{
  port = 5000;
  if (!service_is_unknown(port:port)) exit(0, "The service on port " + port + " has been previously identified.");
}
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Check if Keystone is listening.
res = http_send_recv3(
  method       : "GET",
  item         : "/",
  port         : port,
  exit_on_fail : TRUE
);
if (max_index(res) <= 2) audit(AUDIT_NOT_LISTEN, app, port);

json = json_read(res[2]);
if (
  isnull(json) ||
  isnull(json[1]) ||
  isnull(json[0]) ||
  isnull(json[0]["error"]) ||
  json[0]["error"]["message"] != "The action you have requested has not been implemented."
) audit(AUDIT_NOT_LISTEN, app, port);

# Send a request that will allow us to distinguish between service and
# admin ports.
res = http_send_recv3(
  method       : "GET",
  item         : "/v2.0/users",
  port         : port,
  exit_on_fail : TRUE
);

if (res[0] =~ "^HTTP/[\d.]+ +404 ")
{
  api = "Service";
}
else
{
  json = json_read(res[2]);
  if (
    !isnull(json) &&
    !isnull(json[1]) &&
    !isnull(json[0]) &&
    !isnull(json[0]["error"]) &&
    json[0]["error"]["message"] == "The request you have made requires authentication."
  ) api = "Admin";
}

# We can only trust that this is Keystone if it responded in a known
# way to our API request.
if (isnull(api)) audit(AUDIT_NOT_LISTEN, app, port);

# Register the installed instance.
name = "openstack_keystone";
installs = add_install(
  installs : NULL,
  port     : port,
  dir      : "",
  appname  : name,
  ver      : UNKNOWN_VER
);

set_kb_item(name:"www/"+port+"/"+name+"/"+tolower(api), value:TRUE);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : app + " (" + api + " API)",
    installs     : installs,
    port         : port
  );
}

security_note(port:port, extra:report);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62352);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/08 22:04:49 $");

  script_name(english:"OpenStack Glance Detection");
  script_summary(english:"Looks for the OpenStack Glance API.");

  script_set_attribute(attribute:"synopsis", value:
"An instance of OpenStack Glance was found on the remote host.");
  script_set_attribute(attribute:"description", value:
"OpenStack Glance, a Python application that provides services for
managing virtual machine images, was found on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.net/glance");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openstack:glance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 9191, 9292);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("json.inc");
include("misc_func.inc");
include("path.inc");
include("webapp_func.inc");

app = "OpenStack Glance";

# Get the ports that webservers have been found on.
port = get_kb_item("Services/www");
if (isnull(port))
{
  port = 9191;
  if (!service_is_unknown(port:port)) exit(0, "The service on port " + port + " has been previously identified.");
}
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Check if Glance is listening.
path = "/images";
res = http_send_recv3(
  method       : "GET",
  item         : path,
  port         : port,
  exit_on_fail : TRUE
);
if (max_index(res) <= 2) audit(AUDIT_NOT_LISTEN, app, port);

# Both types of Glance APIs respond with JSON object literals.
json = json_read(res[2]);
if (
  isnull(json) ||
  isnull(json[1]) ||
  isnull(json[0]) ||
  typeof(json[0]) != "array"
) audit(AUDIT_NOT_LISTEN, app, port);

if (!isnull(json[0]["images"]))
{
  type = "Registry";
  dir = "";
}
else if (!isnull(json[0]["versions"]))
{
  # Choose the current version of the API.
  foreach ver (json[0]["versions"])
  {
    if (typeof(ver) != "array")
      continue;

    if (ver["status"] != "CURRENT")
      continue;

    links = ver["links"];
    if (isnull(links))
      continue;

    foreach link (links)
    {
      if (isnull(link["href"]))
        continue;

      matches = eregmatch(string:link["href"], pattern:"^https?://[^/]+(/v.+)/$");
      if (!isnull(matches))
      {
        dir = matches[1];
        break;
      }
    }

    if (!isnull(dir))
      break;
  }

  if (!isnull(dir))
  {
    res = http_send_recv3(
      method       : "GET",
      item         : dir + path,
      port         : port,
      exit_on_fail : TRUE
    );

    json = json_read(res[2]);
    if (
      !isnull(json) &&
      !isnull(json[1]) &&
      !isnull(json[0]) &&
      typeof(json[0]) == "array" &&
      !isnull(json[0]["images"])
    ) type = "API";
  }
}

# We can only trust that this is Glance if it responded in a known way
# to our API request.
if (isnull(type)) audit(AUDIT_NOT_LISTEN, app, port);

# Register the installed instance.
name = "openstack_glance";
installs = add_install(
  installs : NULL,
  port     : port,
  dir      : dir,
  appname  : name,
  ver      : UNKNOWN_VER
);

set_kb_item(name:"www/"+port+"/"+name+"/"+tolower(type), value:TRUE);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : app + " (" + type + " Service)",
    installs     : installs,
    port         : port
  );
}

security_note(port:port, extra:report);

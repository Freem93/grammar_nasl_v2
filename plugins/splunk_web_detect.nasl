#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47619);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/03/02 21:52:02 $");

  script_name(english:"Splunk Web Detection");
  script_summary(english:"Looks for the Splunk login page.");

  script_set_attribute(attribute:"synopsis", value:
"An infrastructure monitoring tool is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"The web interface for Splunk is running on the remote host. Splunk is
a search, monitoring, and reporting tool for system administrators.");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/en_us/products.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Splunk";
port = get_http_port(default:8000, embedded:TRUE);
dir = '/';
build = FALSE;
version = NULL;

# nb: the service will restart if webmirror.nasl successfully accesses
#     /services/server/control/restart so we try several times waiting
#     for it to come back up.
for (tries=5; tries>0; tries--)
{
  res = http_send_recv3(
    method         : 'GET',
    item           : dir,
    port           : port,
    add_headers    : make_array("User-Agent", "Nessus"),
    follow_redirect: 2
  );
  if (!isnull(res)) break;
  sleep(5);
}
if (isnull(res)) audit(AUDIT_RESP_NOT,port,"a HTTP GET request",code:1);

version = UNKNOWN_VER;
license = FALSE;
if (
  ('<b>Login to Splunk</b>' >< res[2] && '<h2><b>Welcome to Splunk</b></h2' >< res[2]) ||
  (
    '<meta name="author" content="Splunk Inc."'   >< res[2] &&
    "Splunk.util.normalizeBoolean('"        >< res[2] &&
     egrep(pattern:"Login *-", string:res[2]) &&
     egrep(pattern:'<p class="footer">&copy; [0-9-]+ Splunk Inc. Splunk', string:res[2])
  ) ||
  # 3.x
  (
    '<title>Splunk' >< res[2] && 'layerid="splunksMenu"' >< res[2] &&
    'href="http://www.splunk.com">Splunk Inc' >< res[2]
  ) ||
  # 4.0.x
  (
    '<meta name="author" content="Splunk Inc."'   >< res[2] &&
    egrep(pattern:'<p class="footer">&copy; [0-9-]+ Splunk Inc. Splunk', string:res[2]) &&
    'class="splButton-primary"' >< res[2]
  ) ||
  # 6.2.x
  (
    '<meta name="author" content="Splunk Inc."' >< res[2] &&
    '<script type="text/json" id="splunkd-partials">' >< res[2]
  )
)
{
  if ('"licenseType": ' >< res[2] || '"license_labels":' >< res[2])
  {
    if ('"licenseType": "free"' >< res[2])
      license = "Free";
    else if ('"license_labels":["Splunk Free' >< res[2])
      license = "Free";
    else if ('"licenseType": "pro"' >< res[2])
      license = "Enterprise";
    else if ('"license_labels":["Splunk Enterprise' >< res[2])
      license = "Enterprise";
    else if ('"product_type":"enterprise"' >< res[2])
      license = "Enterprise";
    else if ('"license_labels":["Splunk Light' >< res[2])
      license = "Light";
    else if ('"product_type":"lite' >< res[2])
      license = "Light";
    else if ('"license_labels":["Splunk Forwarder' >< res[2])
      license = "Forwarder";
  }

  # Check if we can get the version...
  regex = "Login *- *Splunk ([0-9.]+) *(\(([0-9]+)\))?</title>";
  line = egrep(pattern:regex,string:res[2]);
  if (line)
  {
    matches = eregmatch(pattern:regex,string:line);
    if (matches)
    {
      version = matches[1];
      if (matches[3]) build = matches[3];
    }
  }

  if (version == UNKNOWN_VER)
  {
    regex = ">&copy; [0-9-]+ Splunk Inc. Splunk ([0-9.]+) *(build ([0-9]+).)?</p>";
    line = egrep(pattern:regex,string:res[2]);
    if (line)
    {
      matches = eregmatch(pattern:regex,string:line);
      if (matches)
      {
        version = matches[1];
        if (matches[3]) build = matches[3];
      }
    }
  }

  if (version == UNKNOWN_VER)
  {
    regex = '<div id="footer" versionNumber="([0-9.]+)" *(buildNumber="([0-9]+)")? *installType="prod"';
    line = egrep(pattern:regex,string:res[2]);
    if (line)
    {
      matches = eregmatch(pattern:regex, string:line);
      if (matches)
      {
        version = matches[1];
        if (matches[3]) build = matches[3];
      }
    }
  }

  if (version == UNKNOWN_VER)
  {
    regex = '"build":"?([a-f0-9]+)"?,.*,"version":"([0-9.]+)"';
    line = egrep(pattern:regex,string:res[2]);
    if (line)
    {
      matches = eregmatch(pattern:regex, string:line);
      if (matches)
      {
        version = matches[2];
        if (matches[1]) build = matches[1];
      }
    }
  }

  if (version !~ "^[0-9.]+$")
    version = UNKNOWN_VER;

  # Normalize version to X.Y.Z, ie : 4.1 denotes 4.1.0
  if(version =~ "^[0-9]+\.[0-9]+$")
    version += ".0";

  extranp = make_array("isapi", FALSE,"isweb", TRUE);
  extra = make_array("Web interface", TRUE);
  if (license)
    extra["License"] = license;
  if (build)
    extra["Build"] = build;

  register_install(
    app_name : app,
    port     : port,
    version  : version,
    path     : dir,
    extra    : extra,
    extra_no_report : extranp,
    webapp   : TRUE
  );

  report_installs(app_name:app, port:port);

}
else audit (AUDIT_WEB_APP_NOT_INST, app, port);

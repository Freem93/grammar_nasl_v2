#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49069);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:28:15 $");

  script_name(english:"Splunk Management API Detection");
  script_summary(english:"Attempts to access Splunk via REST API.");

  script_set_attribute(attribute:"synopsis", value:
"An infrastructure monitoring tool is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote web server is an instance of the Splunk management API.
Splunk is a search, monitoring, and reporting tool for system
administrators.");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/en_us/products.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.splunk.com/restapi");
  # https://answers.splunk.com/answers/156/what-uses-the-management-port.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3aa0f4e2");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/en_us/download/universal-forwarder.html");
  script_set_attribute(attribute:"solution", value:"
Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:universal_forwarder");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8089);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:8089, embedded:TRUE);
app = "Splunk";
banner = get_http_banner(port:port);
if (isnull(banner)) audit(AUDIT_WEB_BANNER_NOT,port);

headers = parse_http_headers(status_line:banner, headers:banner);
if (isnull(headers))
  audit(AUDIT_FN_FAIL,'parse_http_headers');

server = headers['server'];
if (isnull(server))
  audit(AUDIT_WEB_NO_SERVER_HEADER,port);

if ('Splunkd' >!< server)
  audit(AUDIT_WRONG_WEB_SERVER,port,"Splunkd");

url = '/services/server/info';

# nb: the service will restart if webmirror.nasl successfully accesses
#     /services/server/control/restart so we try several times waiting
#     for it to come back up.
for (tries=5; tries>0; tries--)
{
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (!isnull(res)) break;
  sleep(5);
}
if (isnull(res)) audit(AUDIT_RESP_NOT,port,"a HTTP GET request",code:1);

if (
  (
    '401 ' >< res[0] &&
    'Basic realm="/splunk"' >< res[1]
  ) ||
  (
    '/server/info/server-info' >< res[2] &&
    '<s:key name="version">' >< res[2]
  )
)
{

  build = FALSE;
  ver = NULL;
  license = FALSE;
  server_roles = make_list();

  foreach line (split(res[2], keep:FALSE))
  {
    if ('<s:key name="build">' >< line)
    {
      build = strstr(line, '<s:key name="build">') - '<s:key name="build">';
      build = build - strstr(build, '</s:key>');
      if ('\n' >< build || '"' >< build || !ereg(pattern:"^[0-9][^'<>]*$", string:build)) build = "";
    }
    # 6.2.x
    else if ('<s:key name="product_type">enterprise</s:key>' >< line)
      license = "Enterprise";
    else if ('<s:key name="product_type">lite' >< line)
      license = "Light";
    else if (!license && '<s:key name="isFree">' >< line)
    {
      free = strstr(line, '<s:key name="isFree">') - '<s:key name="isFree">';
      free = free - strstr(free, '</s:key>');
      # nb: the KB item name should use "splunk" not "splunkd".
      if (free == 0)
        license = "Enterprise";
      else if (free == 1)
        license = "Free";
    }
    # Detect Splunk Universal Forwarder and other server roles
    else if ('<s:key name="server_roles">' >< line)
    {
      start = stridx(res[2], '<s:key name="server_roles">');
      end = stridx(res[2], '</s:key>', start);
      
      server_roles_block = substr(res[2], start, end);
      if (isnull(server_roles_block)) continue;

      block_lines = split(server_roles_block, sep:'\n');
      foreach block_line (block_lines)
      { 
        matches = eregmatch(string:block_line, pattern:"<s:item>(.*)</s:item>");
        if (!empty_or_null(matches[1]))
        {
          if (matches[1] == "universal_forwarder")
            app = "Splunk Universal Forwarder";
          server_roles = make_list(server_roles, matches[1]);
        }
      }
    }
    else if ('<s:key name="version">' >< line)
    {
      ver = strstr(line, '<s:key name="version">') - '<s:key name="version">';
      ver = ver - strstr(ver, '</s:key>');
      if ('\n' >< ver || '"' >< ver || !ereg(pattern:"^[0-9][^'<>]*$", string:ver)) ver = UNKNOWN_VER;
    }
    if (!isnull(build) && !isnull(ver))
      break;
  }

  # Normalize version to X.Y.Z, ie : 4.1 denotes 4.1.0
  if(ver =~ "^[0-9]+\.[0-9]+$")
    ver += ".0";

  # We've only ever seen numeric versions from splunk
  # if they start adding non-numerics flag the version
  # as unknown
  if(ver !~ "^[0-9.]+$")
    ver = UNKNOWN_VER;

  extranp = make_array("isapi", TRUE,"isweb",FALSE);
  extra = make_array("Management API", TRUE);
  if (license)
    extra["License"] = license;
  if (build)
    extra["Build"] = build;
  if (!empty(server_roles))
    extra["Server Roles"] = server_roles;

  register_install(
    app_name : app,
    port     : port,
    version  : ver,
    path     : "/",
    extra    : extra,
    extra_no_report : extranp,
    webapp   : TRUE
  );
  report_installs(app_name:app,port:port);

}
else audit(AUDIT_WEB_APP_NOT_INST, app+" Web management API", port);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97212);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/02/16 22:27:01 $");

  script_name(english:"McAfee ePolicy Orchestrator Agent Remote Log Detection");
  script_summary(english:"McAfee ePO Agent remote log detection.");

  script_set_attribute(attribute:"synopsis", value:
"A security management application agent running on the remote host
allows remote access to its logs.");
  script_set_attribute(attribute:"description", value:
"McAfee ePolicy Orchestrator (ePO) Agent is running on the remote host,
and its logs are viewable by unauthenticated, remote users. This is
not the default behavior.");
  # Agents are managed by ePolicy Orchestrator
  script_set_attribute(attribute:"see_also", value:"https://www.mcafee.com/us/products/epolicy-orchestrator.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator_agent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8081);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "McAfee ePO Agent";
port = get_http_port(default:8081, embedded:TRUE);
dir = "/";

# see if agent log is accessible
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir
);

if (empty_or_null(res) || "200" >!< res[0]) audit(AUDIT_NOT_DETECT, app, port);

status = NULL;
body = NULL;
pattern = NULL;
# Note: the regexes below could apply to more versions than listed
# 4.8.0.x
if (res[2] =~ "^<\?xml")
{
  status = res[0];
  body = res[2]; # grab xml

  # another banner grab
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : "/frameworklog.xsl"
  );

  if (!empty_or_null(res) &&
    "200" >< res[0] &&
    "McAfee Agent Activity Log" >< res[2]
  )
  {
    found = strstr(res[2], "<version>");
    if (!isnull(found)) res[2] = found; # shorten response
    # xml
    pattern = ".*<version>([0-9\.]+)<\/version>.*";
  }
}
# 5.0.4.x
else
{
  if ("McAfee Agent Activity Log" >< res[2])
  {
    # grab version from another page
    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : "/agentlog.json"
    );

    if (!empty_or_null(res))
    {
      # JSON
      pattern = '"Version":"([0-9\\.]+)"';
      status = res[0];
      body = res[2];
    }
  }
}

version = NULL;
if (!isnull(body) && "200" >< status && !isnull(pattern))
{
  # extract version
  match = pregmatch(pattern:pattern, string:body, icase:TRUE);
  if (!isnull(match)) version = match[1];
}

if (isnull(version)) audit(AUDIT_NOT_DETECT, app, port);

register_install(app_name:app, path:dir, version:version, port:port, webapp:TRUE);
report_installs(app_name:app, port:port);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32397);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/08/29 16:35:33 $");

  script_name(english:"McAfee Common Management Agent Detection");
  script_summary(english:"Checks the version of McAfee CMA.");

  script_set_attribute(attribute:"synopsis", value:
"A security management service is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"McAfee Common Management Agent (CMA), a component of McAfee's ePolicy
Orchestrator (ePO) system security management solution, is running on
the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.mcafee.com/us/products/epolicy-orchestrator.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:mcafee_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:common_management_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8081);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:8081, embedded: 1);

# Grab the initial page
res = http_send_recv3(port:port, method:"GET", item:"/", exit_on_fail:TRUE);
res = res[2];

appname = "McAfee Agent";
version = NULL;
computer_name = NULL;

# If it looks like a CMA
if (res =~ 'href="FrameworkLog[^.]*.xsl"' && "<ePOServerName>" >< res)
{
  # - version number
  item = eregmatch(pattern:"<version>([^<]+)</ver", string:res);
  if (!isnull(item) && !isnull(item[1]))
  {
    if (item[1] !~ "^[0-9.]+$")
      audit(AUDIT_NONNUMERIC_VER, "McAfee Common Management Agent", port, item[1]);

    version = item[1];
  }

  # - computer name
  item = eregmatch(pattern:"<ComputerName>([^<]+)</Computer", string:res);
  if (!isnull(item) && !isnull(item[1]))
  {
    computer_name = item[1];
  }

  extra = make_array();
  if(!empty_or_null(computer_name))
    extra['Computer Name'] = computer_name;

  register_install(
  app_name:appname,
  path:"/",
  port:port,
  version:version,
  webapp: TRUE,
  extra:extra,
  cpe:"cpe:/a:mcafee:mcafee_agent");

  report_installs();

}
else audit(AUDIT_NOT_DETECT, 'McAfee Agent', port);

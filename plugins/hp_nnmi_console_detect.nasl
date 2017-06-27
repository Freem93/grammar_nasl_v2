#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70146);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/17 14:59:29 $");

  script_name(english:"HP Network Node Manager i (NNMi) Console Detection");
  script_summary(english:"Looks for the error page.");

  script_set_attribute(attribute:"synopsis", value:
"A web management application is running on the remote web server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running the Network Node Manager i (NNMi) console,
a web interface for managing NNMi.");
  # http://www8.hp.com/us/en/software-solutions/network-node-manager-i-network-management-software/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7499aff3");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:network_node_manager_i");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

# The JBoss web server that NNMi installs hosts several applications,
# one of which contains the web UI and web services. We referred to that here
# as the NNMi Console for lack of a better name.

app = "HP Network Node Manager i";
port = get_http_port(default:80);

##
# Looks up the major and minor version found in the help documentation.
# For example, 9.10, 10.10, or 10.20.
#
# @return Version string on success or UNKNOWN_VER otherwise.
##
function get_version()
{
  local_var ver_resp = http_send_recv3(
    port         : port,
    method       : "GET",
    item         : "/nnmDocs_en/htmlHelp/nmHelp/Content/nmHelp/nmWelcome.htm",
    exit_on_fail : FALSE);
  if (isnull(ver_resp) || "200" >!< ver_resp[0]) return UNKNOWN_VER;

  local_var pattern = 'Network Node Manager (?:<span class="_HPc_Basic_Variables_HP_Product_Version">)?([0-9.]+)';
  local_var ver = eregmatch(pattern:pattern, string:ver_resp[2]);
  if (isnull(ver)) return UNKNOWN_VER;

  return ver[1];
}

res = http_send_recv3(
  port         : port,
  method       : "GET",
  item         : "/nnm/main",
  exit_on_fail : TRUE);

script_message = "// HP Support only: The NNMi console can be launched in various debug modes";
if (isnull(res[2]) || script_message >!< res[2]) audit(AUDIT_NOT_DETECT, app, port);

version = get_version();

register_install(
  port     : port,
  app_name : app,
  path     : "/nnm/",
  version  : version,
  webapp   : TRUE);

report_installs(app_name:app,port:port);

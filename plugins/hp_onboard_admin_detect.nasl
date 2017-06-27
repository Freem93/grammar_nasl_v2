#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70140);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/11/26 14:27:46 $");

  script_name(english:"HP Onboard Administrator Detection");
  script_summary(english:"Check XML data response.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is an HP Onboard Administrator.");
  script_set_attribute(attribute:"description", value:"HP Onboard Administrator was found.");

  script_set_attribute(attribute:"see_also", value:"http://www8.hp.com/us/en/products/oas/product-detail.html?oid=3188465");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:onboard_administrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

##
# Search xmldata?item=all with a given regular expression.
#
# @anonparam xmldata The output of xmldata?item=all.
# @anonparam pattern Regular expression containing one capturing group.
#
# @return Content of captured group or NULL if no match.
##
function parse_xmldata()
{
  local_var xmldata, pattern;
  xmldata = _FCT_ANON_ARGS[0];
  pattern = _FCT_ANON_ARGS[1];

  # Strip newlines to avoid multi-line regex because it is taboo.
  xmldata = str_replace(string:xmldata, find:'\n', replace:"");

  # Attempt the match
  local_var m;
  m = eregmatch(string:xmldata, pattern:pattern);

  if (isnull(m))
    return NULL;

  return m[1];
}

##
# Extract product name from the contents of <PN> in <MP> from xmldata?item=all.
# <PN> tags will be stripped.
#
# Examples of strings we find and extract from:
#   * <PN>BladeSystem c7000 DDR2 Onboard Administrator with KVM</PN>
#   * <PN>BladeSystem c7000 Onboard Administrator</PN>
#
# @anonparam xmldata The output of xmldata?item=all
#
# @return The product name of the device, or NULL if not found.
##
function parse_product_name()
{
  local_var xmldata;
  xmldata = _FCT_ANON_ARGS[0];

  # <PN> will appear elsewhere, we want the one within <MP>.
  return parse_xmldata(xmldata, "<MP>.*?<PN>(.*?)</PN>.*?</MP>");
}

##
# Extract firmware version from the contents of <FWRI> in <MP> from xmldata?item=all.
# <FWRI> tags will be stripped.
#
# Examples of strings we find and extract from:
#   * <FWRI>2.32</FWRI>
#
# @anonparam xmldata The output of xmldata?item=all
#
# @return The firmware version of the device, or NULL if not found.
##
function parse_firmware()
{
  local_var xmldata;
  xmldata = _FCT_ANON_ARGS[0];

  # <FWRI> will appear elsewhere, we want the one within <MP>.
  return parse_xmldata(xmldata, "<MP>.*?<FWRI>\s*(.+?)\s*</FWRI>.*?</MP>");
}

app = "HP Onboard Administrator";

port = get_http_port(default:443, embedded:TRUE);

# /xmldata?item=all is used by HP Systems Insight Manager to collect inventory
# and data on a device. The same is true for iLO servers.
res = http_send_recv3(
  method       : "GET",
  item         : "/xmldata?item=all",
  port         : port,
  exit_on_fail : TRUE
);

# Would be encountered in the event of a 404.
if (isnull(res[2]))
{
  audit(AUDIT_NOT_DETECT, app, port);
}

# We can not simply check for the string across the entire XML file
# as iLO has been seen with <MANAGER>Onboard Administrator</MANAGER>.
# Example product name: "BladeSystem c7000 DDR2 Onboard Administrator with KVM"
product_name = parse_product_name(res[2]);
if ("Onboard Administrator" >!< product_name)
{
  audit(AUDIT_WRONG_WEB_SERVER, port, app);
}

# Save our findings.
kb = "Host/HP/Onboard_Administrator";
set_kb_item(name:kb, value:TRUE);
set_kb_item(name:kb + "/Port", value:port);
set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);

fw_ver = parse_firmware(res[2]);
if (!isnull(fw_ver))
{
  set_kb_item(name:kb + "/Version", value:fw_ver);
}

# Report our findings.
report = NULL;
if (!isnull(fw_ver) && report_verbosity > 0)
{
  report =
    '\n  Firmware version : ' + fw_ver +'\n';
}

security_note(port:0, extra:report);

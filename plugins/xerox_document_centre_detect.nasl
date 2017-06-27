#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18100);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/11/05 20:37:10 $");

  script_name(english:"Xerox Document Centre Device Detection");
  script_summary(english:"Checks for Xerox Document Centre devices");

  script_set_attribute(attribute:"synopsis", value:"The remote host is a printer.");
  script_set_attribute(attribute:"description", value:"The remote host is a Xerox Document Centre device.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:document_centre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");

  script_dependencies("httpver.nasl", "broken_web_server.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if (!banner)  audit(AUDIT_WEB_BANNER_NOT, port);
if ("Xerox_MicroServer" >!< banner && "Server: Webserver" >!< banner)
  exit(0, "The web server listening on port "+ port +" is not a Xerox Document Centre MicroServer.");


kb_base = "www/xerox_document_centre";
labels["model"] = "Model";
labels["ess"]   = "Net Controller Software Version";


# Collect various pieces of data.
data = make_array();

res = http_send_recv3(
  method : "GET",
  item   : "/poDeviceProfile.dhtml",
  port   : port,
  exit_on_fail : TRUE
);

# - The Device Profile page (in the Properties tab).
#
#   Examples
#     '<TITLE>Document Centre 220/230</TITLE>'
#     '<TITLE>Xerox Document Centre 332/340 ST</TITLE>'
pat = "<TITLE>(Xerox )?Document Centre ([^<]+)</TITLE>";
matches = egrep(pattern:pat, string:res[2], icase:TRUE);
if (matches)
{
  foreach match (split(matches, keep:FALSE))
  {
    item = eregmatch(pattern:pat, string:match);
    if (!isnull(item))
    {
      data["model"] = item[2];
      break;
    }
  }
}
if (max_index(keys(data)) == 0)
  audit(AUDIT_HOST_NOT, "a Xerox Document Centre device");

# - The ESS level.
#
# nb: the actual level occurs two lines after the label, which will
#     not always be in English.
i = 0;
foreach line (split(res[2], keep:FALSE))
{
  if (line =~ "<td width=50%>.+ESS.*:$")
  {
    data["ess"] = lines[i+2];
    break;
  }
  ++i;
}


# Update KB and report findings.
set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
set_kb_item(name:kb_base, value:TRUE);

max_label_len = 0;
foreach key (keys(data))
{
  label = labels[key];
  if (strlen(label) > max_label_len) max_label_len = strlen(label);
}

info = "";
foreach key (make_list("model", "ssw", "sdc", "ess"))
{
  val = data[key];
  if (!isnull(val))
  {
    set_kb_item(name:kb_base+"/"+key, value:val);

    label = labels[key];
    if (key == "model") val = 'Xerox Document Centre ' + val;
    info += '  ' + label + crap(data:" ", length:max_label_len-strlen(label)) + ' : ' + val + '\n';
  }
}

if (report_verbosity > 0) security_note(port:port, extra:'\n'+info);
else security_note(port);

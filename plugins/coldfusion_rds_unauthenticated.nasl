#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55513);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/14 20:50:06 $");

  script_name(english:"Adobe ColdFusion Remote Development Services Enabled Without Authentication");
  script_summary(english:"Queries unauthenticated RDS installs.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has ColdFusion RDS enabled without authentication.");
  script_set_attribute(attribute:"description", value:
"ColdFusion's Remote Development Services allow developers to use IDEs
such as Dreamweaver to manage applications. The remote host has RDS
enabled without authentication. This means that a remote attacker can
read and write files on the affected system.");
  # https://helpx.adobe.com/coldfusion/kb/disabling-enabling-coldfusion-rds-production.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3483a520");
  script_set_attribute(attribute:"solution", value:
"Either disable RDS or enable RDS authentication through the
administrator console.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/05");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_rds_detect.nasl");
  script_require_keys("installed_sw/ColdFusion");
  script_require_ports("Services/www", 80, 8500);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);

global_var port, dir;


function get_string(blob)
{
  local_var len1, len2, matches, s;

  # Find out how long the string is.
  matches = eregmatch(string:blob, pattern:"^([0-9]+):");
  if (isnull(matches)) exit(1, "Failed to parse response string (" + blob + ") from the ColdFusion install at "+build_url(port:port, qs:dir+'/'));
  len1 = strlen(matches[0]);
  len2 = int(matches[1]);

  # Parse out the string.
  s = substr(blob, len1, len1 + len2 - 1);

  # Cut off the section of the blob we've used.
  blob = substr(blob, len1 + len2);
  if (isnull(blob)) blob = "";

  return make_list(blob, s);
}

function parse_blob(blob)
{
  local_var items, matches, name, result, size, type;

  # Create a data structure to organize file and directory information.
  items = make_array();
  items["D"] = make_array();
  items["F"] = make_array();

  # We don't really need to know the number of fields.
  blob = ereg_replace(string:blob, pattern:"^[0-9]+:", replace:"");

  while (blob)
  {
    # The first two items are colon separated.
    matches = eregmatch(string:blob, pattern:"^([0-9]+):(.):");
    if (isnull(matches)) exit(1, "Failed to parse response string (" + blob + ") from the ColdFusion install at "+build_url(port:port, qs:dir+'/'));
    type = matches[2];

    # Remove the portion of the blob we've parsed so far.
    blob = substr(blob, strlen(matches[0]));

    # Get the name of the file or directory.
    result = get_string(blob:blob);
    blob = result[0];
    name = result[1];

    # Get the next field (ignored).
    result = get_string(blob:blob);
    blob = result[0];

    # Get the size of the file or directory.
    result = get_string(blob:blob);
    blob = result[0];
    size = int(result[1]);

    # Get the next field (ignored).
    result = get_string(blob:blob);
    blob = result[0];

    # Silently ignore unrecognized types.
    if (type != "D" && type != "F") continue;

    items[type][name] = size;
  }

  return items;
}

# Get details of ColdFusion install.
port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];

# Ignore installations that don't have RDS or require authentication.
auth = get_kb_item("coldfusion/" + port + "/rds/auth");
if (isnull(auth)) exit(0, "RDS is not enabled on port " + port + ".");
if (auth) exit(0, "RDS on port " + port + " requires authentication and is therefore not affected.");

if (report_verbosity > 0)
{
  res = get_kb_item_or_exit("/tmp/coldfusion/" + port + "/rds/BrowseDir_Studio");
  items = parse_blob(blob:res);

  report = '\n' + "Here is a directory listing of 'C:\' :" + '\n';
  foreach type (make_list("D", "F"))
  {
    foreach name (sort(keys(items[type])))
    {
      if (type == "D")
        report += '\n  \\' + name;
      else
        report += '\n  ' + name + ' (' + items[type][name] + ' bytes)';
    }
  }
  report += '\n';

 security_warning(port:port, extra:report);
}
else security_warning(port);

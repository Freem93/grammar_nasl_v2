#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66189);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/04/23 16:37:18 $");

  script_name(english:"JBoss Web Services Endpoint Enumeration");
  script_summary(english:"Looks at page that lists registered endpoints");

  script_set_attribute(attribute:"synopsis", value:"A Java-based web services framework is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"JBossWS, a framework similar to JAX-WS for making Java EE web services,
is listening on the remote host and lists its registered endpoints.");

  script_set_attribute(attribute:"see_also", value:"http://www.jboss.org/jbossws/");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/23");

  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:jboss:jbossws");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/jboss");
  script_require_ports("Services/www", 80, 443, 8080);

  exit(0);
}

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

# Note that v7 and above no longer list JBoss in the server headers,
# which is okay since this check only works on instances older v7.
get_kb_item_or_exit("www/jboss");

# Get the ports that webservers have been found on, defaulting to what
# JBossWS uses.
port = get_http_port(default:8080);

# Access the list of endpoints, this URL only works in older versions.
res = http_send_recv3(
  method       : "GET",
  item         : "/jbossws/services",
  port         : port,
  exit_on_fail : TRUE
);

# Confirm that the page looks as expected.
headers = parse_http_headers(status_line:res[0], headers:res[1]);
if (
  headers["$code"] != 200 ||
  "<title>JBossWS" >!< res[2] ||
  "<div class='pageHeader'>JBossWS/Services</div>" >!< res[2]
)
{
  exit(0, "Failed to retrieve a list of JBoss WS endpoints on port " + port + ".");
}

# Store the fact that JBossWS is running on the remote host in the KB.
set_kb_item(name:"JBossWS", value:port);

# Parse the list of endpoints from the page.
regex = join(make_list(
  "<tr>",
  "<td>Endpoint Name</td>",
  "<td>([^<]+)</td>",
  "</tr>",
  "<tr>",
  "<td>Endpoint Address</td>",
  "<td>",
  "<a\s+[^>]*>([^<]+)</a>",
  "</td>",
  "</tr>"),
  sep:"\s*"
);

i = 0;
endpoints = make_list();
while (TRUE)
{
  # Parse an endpoint name and address from the page.
  matches = eregmatch(string:res[2], pattern:regex);
  if (isnull(matches))
    break;
  name = matches[1];
  addr = matches[2];

  # Remove the endpoint from the page so we can reuse the regex.
  res[2] = str_replace(string:res[2], find:matches[0], replace:"");

  # Extract the path and prune the query string.
  fields = split_url(url:addr);
  if (isnull(fields))
    continue;
  addr = ereg_replace(string:fields["page"], pattern:"^([^?]+).*$", replace:"\1");

  # Append the endpoint to our list.
  endpoint = make_array("name", name, "addr", addr);
  endpoints[i++] = endpoint;

  # Store the endpoint information in the KB.
  kb = "JBossWS/" + port + "/endpoint/" + i;
  set_kb_item(name:kb + "/name", value:endpoint["name"]);
  set_kb_item(name:kb + "/addr", value:endpoint["addr"]);
}

# Check if we found anything to report.
if (i == 0)
  exit(0, "No endpoints were found on the JBossWS instance on port " + port + ".");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  if (i == 1)
    s = "";
  else
    s = "s";

  report =
    '\nThe JBossWS instance on the remote host exposes the following endpoint' + s + ' :' +
    '\n';

  foreach endpoint (endpoints)
  {
    report +=
      '\n  Name    : ' + endpoint["name"] +
      '\n  Address : ' + build_url(port:port, qs:endpoint["addr"]) +
      '\n';
  }
}

security_note(port:port, extra:report);

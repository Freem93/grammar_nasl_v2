# -------------------------------------------------------------------
# (c) Recx Ltd 2009-2012
# http://www.recx.co.uk/
#
# Look for the Oracle Application Express builder on Apex/HTTP ports
# Version 1.0
# -------------------------------------------------------------------

include("compat.inc");


if (description)
{
  script_id(64706);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/02/22 19:46:31 $");

  script_name(english:"Oracle Application Express (Apex) Administration Interface is Accessible");
  script_summary(english:"Checks for Oracle Apex Version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Oracle Application Express environment on the remote host has the
Administration Builder interface enabled."
  );
  script_set_attribute(
    attribute:"description",
    value:
"In production environments, the Apex Administration and Builder
applications should be disabled to prevent administrator or developer
access to the instance via a web browser."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/developer-tools/apex/index.html" );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:application_express");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2013 Recx Ltd.");

  script_dependencies("http_version.nasl", "oracle_apex_detect.nasl");
  script_require_keys("Oracle/Apex");
  script_require_ports("Services/www", 8080, 443);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

function raise_finding(port, location)
{
  local_var report, url;
  url = build_url(qs:location, port:port);
  if (report_verbosity > 0)
  {
    report = '\nOracle Apex Administration Interface :\n' +
             '\n  URL : ' + url + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}

port = get_http_port(default:8080);

if (!get_port_state(port)) exit(0, "Port " + port + " is not open.");

if(!get_kb_item("Oracle/Apex/" + port))
  exit(0, "The 'Oracle/Apex/" + port + "' KB item is not set.");

# Define Oracle Apex builder patterns.
pattern[0] = "Location:[^\r\n]*f?p=4550";

# App IDs to request, this will redirect to f?p=4550:1:<session>:....
appId[0] = "p=4550:1";

# Get the location of "f" from KB
location = get_kb_item("Oracle/Apex/" + port + "/Location");
if(!location)
  exit(0, "The 'Oracle/Apex/" + port + "/Location' KB item is not set.");

vuln = FALSE;
for(i=0;appId[i];i=i+1)
{
  url = location + "f?" + appId[i];
  result = http_keepalive_send_recv(port: port, data: http_get(port: port, item: url));
  if ( result == NULL )
    exit(1, "Unable to establish connection to server on port " + port + ".");

  for(j=0;pattern[j];j=j+1)
  {
    matches = eregmatch(pattern:pattern[j], string: result, icase:1);
    if (matches)
    {
      raise_finding(port:port, location:location);
      vuln = TRUE;
      set_kb_item(name:"Oracle/Apex/" + port + "/Admin", value:"TRUE");
      break;
    }
  }
}

if(!vuln)
  exit(0, "Oracle Apex Administration Interface does not appear to be listening on port " + port + ".");

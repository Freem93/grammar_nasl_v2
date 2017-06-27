#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55930);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/21 20:28:08 $");

  script_name(english:"Oracle GlassFish HTTP Server Version");
  script_summary(english:"Obtains the version of the remote Oracle GlassFish HTTP Server.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain the version number of the remote Oracle
GlassFish HTTP server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an Oracle GlassFish HTTP Server, a Java
EE application server. It was possible to read the version number from
the HTTP response headers.");
  # http://www.oracle.com/us/products/middleware/cloud-app-foundation/glassfish-server/overview/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85f4fd5a");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 4848, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

app = 'Oracle Glassfish';

# By default, GlassFish listens on port 8080.
port = get_http_port(default:8080);

# Check if this is a GlassFish server.
banner = get_http_banner(port:port);
if (!banner || "Server:" >!< banner || !preg(string:banner, pattern:"(GlassFish|Sun Java System Application Server|Sun-Java-System/Application-Server)", multiline:TRUE, icase:TRUE))
  audit(AUDIT_NOT_DETECT, app);

# Extract Server header from HTTP response headers.
pat = "^Server:.*(((?:Oracle )?GlassFish(?: Enterprise)?|Sun Java System Application Server|Sun-Java-System/Application-Server)[ a-zA-Z]*v?(([.0-9]*)( Patch|_)?\s?([0-9]*)))";
matches = egrep(string:banner, pattern:pat, icase:TRUE);

if (matches)
{
  # Parse version number from Server header.
  foreach match (split(matches, keep:FALSE))
  {
    fields = eregmatch(string:match, pattern:pat, icase:TRUE);
    if (!isnull(fields))
    {
      # Extract the server header's data.
      source = fields[1];

      # Set app name according to header
      app = fields[2];

      # Save the original format of the version number.
      if (!isnull(fields[3])) pristine = fields[3];

      # Incorporate the patchlevel, if existing, into the version number.
      if (!isnull(fields[4])) version = fields[4];
      if (!isnull(fields[5]) && !isnull(fields[6]))
        version += "." + fields[6];
      break;
    }
  }
}

set_kb_item(name:"www/glassfish", value:TRUE);
set_kb_item(name:"www/" + port + "/glassfish", value:TRUE);
if (!isnull(version))
{
  set_kb_item(name:"www/" + port + "/glassfish/source", value:source);
  set_kb_item(name:"www/" + port + "/glassfish/version", value:version);
  set_kb_item(name:"www/" + port + "/glassfish/version/pristine", value:chomp(pristine));
}

if (report_verbosity > 0)
{
  report = '\n' + app;
  if (!isnull(version)) report += ' version '+version;
  report += ' is running on port '+port+'.\n';

  security_note(port:port, extra:report);
}
else security_note(port:port);

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51922);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/09 00:11:21 $");

  script_name(english:"Apache CouchDB Detection");
  script_summary(english:"Looks for CouchDB");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote server is running a document-oriented database system
written in Erlang."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote server is running CouchDB, a document-oriented database
system written in Erlang."
  );
  script_set_attribute(attribute:"see_also", value:"http://couchdb.apache.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 5984);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port     = get_http_port(default:5984);
ver      = NULL;
installs = NULL;
ver_pat  = "^CouchDB/([0-9.]+)";

server_header = http_server_header(port:port);
if (!server_header) exit(0, "The web server on port "+port+" does not include a Server response header in its banner.");
if ("CouchDB" >!< server_header) exit(0, "The Server response header in the banner from the web server on port "+port+" is not from CouchDB.");

matches = eregmatch(pattern:ver_pat, string:server_header);
if (matches[1]) ver = matches[1];

set_kb_item(name:"www/"+port+"/couchdb/source", value:server_header);

installs = add_install(
  installs : installs,
  dir      : '/',
  appname  : 'couchdb',
  ver      : ver,
  port     : port
);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'CouchDB',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);

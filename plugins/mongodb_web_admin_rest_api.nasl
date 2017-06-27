#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81778);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/12 14:46:00 $");

  script_name(english:"MongoDB Unauthenticated REST API Detection");
  script_summary(english:"Detects the MongoDB Unauthenticated REST API.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running an unauthenticated REST API for a
database system.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running an unauthenticated REST API for
MongoDB, a document-oriented database system. A remote attacker can
exploit this API to read arbitrary collections from databases in the
system.");
  script_set_attribute(attribute:"see_also", value:"http://docs.mongodb.org/ecosystem/tools/http-interfaces/");
  script_set_attribute(attribute:"solution", value:
"Disable or restrict access to the MongoDB REST API or the MongoDB HTTP
interface.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mongodb:mongodb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("mongodb_web_admin_detect.nasl");
  script_require_keys("installed_sw/mongodb_web");
  script_require_ports("Services/www", 28017);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

install_name = "mongodb_web";
app_name = "MongoDB Web Admin Interface";

get_install_count(app_name:install_name, exit_if_zero:TRUE);

port = get_http_port(default:28017, embedded:FALSE);

install = get_single_install(app_name:install_name, port:port);

# default collection 'startup_log' in default database 'local'
item = "/local/startup_log/?limit=1";

response = http_send_recv3(
  item:item,
  port:port,
  method:"GET",
  exit_on_fail:TRUE
);

if ("REST is not enabled" >< response[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, build_url(port:port, qs:install['dir']));

if ('"total_rows" : 1' >!< response[2])
  audit(AUDIT_WEB_FILES_NOT, app_name + " REST API", port);

# for pci_reachable_database.nasl
set_kb_item(name:'mongodb_rest', value:port);

security_report_v4(
  port        : port,
  severity    : SECURITY_WARNING,
  request     : make_list(build_url(qs:item, port:port)),
  output      : chomp(response[2]),
  generic     : TRUE
);
exit(0);

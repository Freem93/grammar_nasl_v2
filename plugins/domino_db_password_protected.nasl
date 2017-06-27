#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59852);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/09 20:31:39 $");

  script_name(english:"IBM Domino Password Protected DB Enumeration");
  script_summary(english:"Enumerates the password protected Domino Administration Databases.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service contains at least one password protected database.");
  script_set_attribute(attribute:"description", value:
"It is possible to enumerate the password protected databases on the
remote IBM Domino (formerly IBM Lotus Domino) Server.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("domino_db_no_password.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/domino");

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("http_func.inc");

get_kb_item_or_exit("www/domino");
report = "";

port = get_http_port(default:80);
url = build_url(qs:"/", port:port);

# Get a list of password protected DBs
list = get_kb_list('www/domino/'+port+'/db/password_protected');
if (isnull(list) || max_index(keys(list)) == 0) exit(0, 'No password protected databases were detected on port '+port+'.');

foreach db (list)
  report += "  " + url + db + '\n';

if (report)
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus found the following password-protected Domino databases :' +
      '\n\n' +
      report;
    security_note(port:port, extra:report);
  }
  else security_note(port);
}

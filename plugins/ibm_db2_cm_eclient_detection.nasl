#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70074);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/09/23 20:32:16 $");

  script_name(english:"IBM DB2 Content Manager eClient Detection");
  script_summary(english:"Looks for eClient");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server hosts a content management application."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts IBM DB2 Content Manager eClient, a web-
based content management application."
  );
  # http://pic.dhe.ibm.com/infocenter/cmgmt/v8r5m0/index.jsp?topic=%2Fcom.ibm.eclient.doc%2Fdcmeo000.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b5c9fb6");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2_content_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
app = "IBM DB2 Content Manager eClient";

dirs = make_list(cgi_dirs());

checks = make_array();

regexes = make_list();
regexes[0] = make_list(
  "(IBM )?Content Manager( eClient)?",
  "/eclient/eclient(.+)\.js"
);
regexes[1] = make_list("> Version :[^>]([0-9.]+)\</div\>");

url = "/eclient/IDMLogon2.jsp";
checks[url] = regexes;

installs = find_install(
  appname : "ibm_eclient",
  checks  : checks,
  dirs    : dirs,
  port    : port
);

if (isnull(installs))  audit(AUDIT_WEB_APP_NOT_INST, app, port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : app,
    installs     : installs,
    port         : port,
    item         : url
  );
  security_note(port:port, extra:report);
}
else security_note(port);

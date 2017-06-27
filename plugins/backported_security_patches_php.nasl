#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84574);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/07/07 17:20:51 $");

  script_name(english:"Backported Security Patch Detection (PHP)");
  script_summary(english:"Checks for backported security patches.");

  script_set_attribute(attribute:"synopsis", value:
"Security patches have been backported.");
  script_set_attribute(attribute:"description", value:
"Security patches may have been 'backported' to the remote PHP install
without changing its version number.

Banner-based checks have been disabled to avoid false positives.

Note that this test is informational only and does not denote any
security problem.");
 script_set_attribute(attribute:"see_also", value: "https://access.redhat.com/security/updates/backporting/?sc_cid=3093");
 script_set_attribute(attribute:"solution", value: "n/a");
 script_set_attribute(attribute:"risk_factor", value: "None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl", "ssh_get_info.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
php_backported_on_port = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (php_backported_on_port)
{
  if (report_verbosity > 0)
  {
    if (get_kb_item("Host/local_checks_enabled"))
      info = "Local checks have been enabled.";
    else
      info = "Give Nessus credentials to perform local checks.";

    info = '\n' + info + '\n';
    security_note(port:port, extra:info);
  }
  else security_note(port);
}
else exit(0, "The PHP install on port "+port+" does not appear to have backported security patches.");

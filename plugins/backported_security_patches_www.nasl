#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(39521);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2015/07/07 17:20:51 $");

 script_name(english:"Backported Security Patch Detection (WWW)");
 script_summary(english:"Checks for backported security patches.");

 script_set_attribute(attribute:"synopsis", value:
"Security patches are backported.");
 script_set_attribute(attribute:"description", value:
"Security patches may have been 'backported' to the remote HTTP server
without changing its version number.

Banner-based checks have been disabled to avoid false positives.

Note that this test is informational only and does not denote any
security problem.");
 script_set_attribute(attribute:"see_also", value: "https://access.redhat.com/security/updates/backporting/?sc_cid=3093");
 script_set_attribute(attribute:"solution", value: "n/a");
 script_set_attribute(attribute:"risk_factor", value: "None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/25");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();

 script_category(ACT_END);
 script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
 script_family(english:"General");

 script_dependencie("global_settings.nasl", "http_version.nasl", "apache_http_version.nasl", "tomcat_error_version.nasl", "ssh_get_info.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");

port = get_http_port(default: 80);

backported = FALSE;
if (
  get_kb_item("www/apache/"+port+"/backported") ||
  get_kb_item("tomcat/"+port+"/backported")
)
{
  backported = TRUE;
}
else
{
  banner = get_http_banner(port:port, broken:TRUE);
  if (strlen(banner) == 0) audit(AUDIT_WEB_BANNER_NOT, port);
  banner2 = get_backport_banner(banner:banner);
  if (banner != banner2) backported = TRUE;
}

if (backported)
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
else exit(0, "The web server listening on port "+port+" does not appear to have backported security patches.");

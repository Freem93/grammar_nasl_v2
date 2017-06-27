#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25626);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/30 22:07:39 $");

  script_cve_id("CVE-2007-3502");
  script_bugtraq_id(24692);
  script_osvdb_id(37217);

  script_name(english:"Kaspersky Anti-Spam Control Center Web Config aslic_status.cgi Directory Listing");
  script_summary(english:"Attempts to find a directory listing.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Kaspersky Anti-Spam Control Center installed on the
remote host is affected by an information disclosure vulnerability due
to a failure to require authentication for access to directories under
the service's document root. An unauthenticated, remote attacker can
exploit this to obtain sensitive information from the remote host.

Note that the Control Center listens only on the loopback interface by
default.");
  script_set_attribute(attribute:"solution", value:"Apply Critical Fix 1 for Kaspersky Anti-Spam 3.0 MP1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:kaspersky_lab:kaspersky_anti-spam");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 3080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:3080);

# Make sure it's KAS.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (isnull(banner))
    audit(AUDIT_WEB_BANNER_NOT, port);
  if ("Server: thttpd/" >!< banner)
    audit(AUDIT_WRONG_WEB_SERVER, port, "thttpd");
}

r = http_send_recv3(method:"GET", item:"/aslic_status.cgi", port:port, exit_on_fail:TRUE);
res = r[2];

# If so...
if ("Authorization required for the URL '/aslic_status.cgi'" >< res)
{
  # Try to exploit the vulnerability to get a directory listing.
  r = http_send_recv3(method:"GET", item:"/stat/", port:port, exit_on_fail:TRUE);
  res = r[2];

  # There's a problem if we get a directory listing.
  if ("<TITLE>Index of /stat/</TITLE>" >< res)
  {
    output = strstr(res, "<TITLE>Index");
    if (empty_or_null(output)) output = res;

    security_report_v4(
      port         : port,
      generic      : TRUE,
      severity     : SECURITY_HOLE,
      request      : make_list(build_url(qs:"/stat/", port:port)),
      output       : output
    );
    exit(0);
  }
}
audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);

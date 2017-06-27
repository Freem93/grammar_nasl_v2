#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE

include("compat.inc");

if (description)
{
  script_id(10604);
  script_version("$Revision: 1.33 $");
  script_cvs_date("$Date: 2017/01/03 14:55:09 $");

  script_cve_id("CVE-2000-1050");
  script_bugtraq_id(1830);
  script_osvdb_id(500);
  script_xref(name:"EDB-ID", value:"20313");

  script_name(english:"Allaire JRun Crafted Request Forced Directory Listing");
  script_summary(english:"Attempts to find a directory listing.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Allaire JRun running on the remote host is affected by
an information disclosure vulnerability. An unauthenticated, remote
attacker can exploit this, by using a crafted URL request with '/./'
prepended, to display a listing of a remote directory, even if a valid
index file exists in the directory.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JRun version 3.0sp2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/01/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:macromedia:jrun");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2001-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8000);

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8000);

url = "/./WEB-INF/";
w = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (w[0] =~ "^HTTP.* 200 ")
{
  r = w[2];
  if ("Index of /./WEB-INF/" >< r)
  {
    output = strstr(r, "Index of");
    if (empty_or_null(output)) output = r;

    security_report_v4(
      port         : port,
      generic      : TRUE,
      severity     : SECURITY_WARNING,
      request      : make_list(build_url(qs:url, port:port)),
      output       : output
    );
    exit(0);
  }
}
audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);

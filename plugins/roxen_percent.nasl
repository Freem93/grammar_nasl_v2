#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(10479);
  script_version ("$Revision: 1.26 $");
  script_cvs_date("$Date: 2017/01/03 14:55:09 $");

  script_cve_id("CVE-2000-0671");
  script_bugtraq_id(1510);
  script_osvdb_id(378);
  script_xref(name:"EDB-ID", value:"20104");

  script_name(english:"Roxen Web Server /%00/ Encoded Request Forced Directory Listing");
  script_summary(english:"Attempts to find a directory listing.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure 
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Roxen Web Server running on the remote host is affected
by an information disclosure vulnerability. An unauthenticated, remote
attacker can exploit this, by using a crafted URL request with '/%00/'
appended to the URI, to display a listing of a remote directory, which
may contain sensitive files.");
  script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-07/0307.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of Roxen.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/07/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:roxen:webserver");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2000-2017 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/roxen");

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# Make sure this is Roxen.
get_kb_item_or_exit('www/roxen');

port = get_http_port(default:80);

r = http_send_recv3(port:port, method:"GET", item:"/%00/", exit_on_fail:TRUE);
seek = "Directory listing of";
data = r[2];
if (seek >< data)
{
  output = strstr(data, "Directory listing");
  if (empty_or_null(output)) output = data;

  security_report_v4(
      port         : port,
      generic      : TRUE,
      severity     : SECURITY_WARNING,
      request      : make_list(build_url(qs:"/%00/", port:port)),
      output       : output
    );
    exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Roxen", port);

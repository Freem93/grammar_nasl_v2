#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(10153);
  script_version ("$Revision: 1.41 $");
  script_cvs_date("$Date: 2016/12/30 22:07:39 $");

  script_cve_id("CVE-1999-0269");
  script_bugtraq_id(7621);
  script_osvdb_id(119);

  script_name(english:"Netscape Server ?PageServices Request Forced Directory Listing");
  script_summary(english:"Attempts to find a directory listing.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Netscape Server running on the remote host is affected
by an information disclosure vulnerability. An unauthenticated, remote
attacker can exploit this, by using a crafted URL request with
'?PageServices' appended, to display a listing of the page directory,
which may contain sensitive files.");
  script_set_attribute(attribute:"solution", value:
"Upgrade your Netscape Server or turn off indexing.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"1998/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:netscape:enterprise_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/iplanet");

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

get_kb_item_or_exit("www/iplanet");
port = get_http_port(default:80);

seek = "<title>index of /</title>";
data = http_get_cache(item:"/", port:port, exit_on_fail: TRUE);
data_low = tolower(data);
if(seek >< data_low)
  exit(0, "Directory index found on port "+port);

url = "/?PageServices";
w = http_send_recv3(
  method : "GET",
  item   : url,
  port   : port,
  exit_on_fail : TRUE
);
data = w[2];
data_low = tolower(data);
if (seek >< data_low)
{
  output = strstr(data_low, "<title>index");
  if (empty_or_null(output)) output = data;

  security_report_v4(
      port         : port,
      generic      : TRUE,
      severity     : SECURITY_WARNING,
      request      : make_list(build_url(qs:url, port:port)),
      output       : output
    );
    exit(0);
}
audit(AUDIT_LISTEN_NOT_VULN, "Netscape", port);

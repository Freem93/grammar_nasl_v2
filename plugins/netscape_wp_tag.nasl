#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(10352);
  script_version ("$Revision: 1.37 $");
  script_cvs_date("$Date: 2016/12/30 22:07:39 $");

  script_cve_id("CVE-2000-0236");
  script_bugtraq_id(1063);
  script_osvdb_id(11634);
  script_xref(name:"CERT", value:"32794");
  script_xref(name:"EDB-ID", value:"19814");

  script_name(english:"Netscape Server ?wp-* Publishing Tags Forced Directory Listing");
  script_summary(english:"Attempts to find a directory listing.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Netscape Server running on the remote host is affected
by an information disclosure vulnerability. An unauthenticated, remote
attacker can exploit this, by using a crafted URL request with special
tags such as '?wp-cs-dump' appended, to display a listing of the page
directory, which may contain sensitive files.");
  script_set_attribute(attribute:"solution", value:
"Disable the 'web publishing' feature of the server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/03/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:netscape:enterprise_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

  script_dependencie("find_service1.nasl", "http_version.nasl");
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

res = http_get_cache(item:"/", port:port, exit_on_fail: TRUE);
if ("<title>index of /</title>" >< tolower(res))
 exit(0, "Directory index found on port "+port);

tags = make_list("?wp-cs-dump", "?wp-ver-info", "?wp-html-rend", "?wp-usr-prop",
"?wp-ver-diff", "?wp-verify-link", "?wp-start-ver", "?wp-stop-ver", "?wp-uncheckout");

urls = make_list();
foreach tag (tags)
{
  w = http_send_recv3(method:"GET", item:"/" + tag, port:port, exit_on_fail: TRUE);
  res = w[2];
  if ("<title>index of /</title>" >< tolower(res))
  {
    urls = make_list(urls, build_url(qs:"/" + tag, port:port));
  }
}
if (max_index(urls) == 0)
  audit(AUDIT_LISTEN_NOT_VULN, "Netscape", port);

output = strstr(tolower(res), "<title>index");
if (empty_or_null(output)) output = res;

security_report_v4(
  port         : port,
  generic      : TRUE,
  severity     : SECURITY_WARNING,
  request      : urls,
  output       : output,
  rep_extra    : 'Note that this report includes the directory listing output for the last\nrequest sent.'
  );
exit(0);

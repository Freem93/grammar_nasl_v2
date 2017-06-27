#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56972);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/19 17:45:32 $");

  script_cve_id("CVE-2011-3368", "CVE-2011-4317");
  script_bugtraq_id(49957, 50802);
  script_osvdb_id(76079, 77310);
  script_xref(name:"EDB-ID", value:"17969");

  script_name(english:"Apache HTTP Server mod_proxy Reverse Proxy Information Disclosure");
  script_summary(english:"Make a malformed HTTP request");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The web server running on the remote host has an information
disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apache HTTP Server running on the remote host is
affected by an information disclosure vulnerability. When configured
as a reverse proxy, improper use of the RewriteRule and ProxyPassMatch
directives could cause the web server to proxy requests to arbitrary
hosts. This allows a remote attacker to indirectly send requests to
intranet servers."
  );
  # http://mail-archives.apache.org/mod_mbox/httpd-announce/201110.mbox/%3C20111005141541.GA7696%40redhat.com%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7fedbcf7");
  script_set_attribute(attribute:"see_also", value:"https://community.qualys.com/blogs/securitylabs/tags/cve-2011-4317");
  script_set_attribute(attribute:"see_also", value:"http://thread.gmane.org/gmane.comp.apache.devel/46440");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Apache httpd 2.2.22 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/29");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Make sure this looks like Apache unless paranoid
if (report_paranoia < 2)
{
  server = http_server_header(port:port);

  if ( 'ibm_http_server' >!< tolower(server) && 'apache' >!< tolower(server) && 'oracle http server' >!< tolower(server) && 'oracle-http-server' >!< tolower(server) )
    exit(0, 'The web server on port ' + port + ' doesn\'t look like an Apache-based httpd.');

  # looks like Apache _httpd_
  if ('apache' >< tolower(server) && ( 'coyote' >< tolower(server) || 'tomcat' >< tolower(server)) )
    exit(0, 'The web server on port ' + port + ' doesn\'t look like Apache httpd.');
}

pages = make_list('/');

foreach page (pages)
{
  # GET 1324:@target-host/page
  # misconfigured servers reconstruct the URI as http://intended-host@target-host/page
  # instead of responding with an HTTP 400. this PoC should cover both CVEs
  url = strcat(unixtime(), ':@', get_host_ip(), page);
  res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
  headers = parse_http_headers(status_line:res[0], headers:res[1]);
  http_code = headers['$code'];

  # the patched server should always send a 400. just to be on the safe side,
  # we'll explicitly check for a 200 or 404
  if (http_code == 404 || http_code == 200)
  {
   # GET 1324:@target-host:likely-closed-port/page
   # misconfigured servers reconstruct the URI as http://intended-host@target-host:likely-closed-port/page
   # instead of responding with an HTTP 400. this PoC should cover both CVEs
   url = strcat(unixtime(), ':@localhost:', (rand() % 535 + 65000), page);
   res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
   headers = parse_http_headers(status_line:res[0], headers:res[1]);
   http_code = headers['$code'];

   # the patched server should always send a 400. 
   # we'll explicitly check for a 503 (resulting from trying to connect to a closed port)
   if (http_code == 503)
  {
    # this will prevent the other plugin (that checks for the
    # incomplete fix for this CVE) from running
    set_kb_item(name:'/tmp/CVE-2011-3368', value:TRUE);

    if (report_verbosity > 0)
   {
    report =
      '\nNessus verified this by sending the following request :\n\n' +
      chomp(http_last_sent_request()) + '\n';

    if (report_verbosity > 0)
    {
      report +=
        '\nWhich resulted in a non-400 response :\n\n' +
        res[0] +
        chomp(res[1]) + '\n';
    }

    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
  }
 }
}
exit(1, 'Unable to determine if the system is vulnerable on port ' + port);

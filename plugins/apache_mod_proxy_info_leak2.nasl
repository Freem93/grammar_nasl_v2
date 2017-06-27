#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57875);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/06/16 11:00:58 $");

  script_cve_id("CVE-2011-3639");
  script_bugtraq_id(51869);
  script_osvdb_id(77444);

  script_name(english:"Apache HTTP Server mod_proxy Reverse Proxy HTTP 0.9 Information Disclosure");
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
"The version of Apache HTTP Server running on the remote host has an
information disclosure vulnerability.  When configured as a reverse
proxy, improper use of the RewriteRule and ProxyPassMatch directives
could cause the web server to proxy requests to arbitrary hosts.  This
could allow a remote attacker to indirectly send requests to intranet
servers by making specially crafted HTTP 0.9 requests.

This vulnerability only affects versions 2.2.x before 2.2.18 that have
backported the fix for CVE-2011-3368."
  );
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=722545#c15");
  script_set_attribute(attribute:"see_also", value:"http://article.gmane.org/gmane.comp.apache.devel/45983");
  script_set_attribute(attribute:"see_also", value:"http://svn.apache.org/viewvc?view=revision&revision=1188745");
  script_set_attribute(
    attribute:"solution",
    value:"Contact the distro/vendor for the latest update of Apache httpd."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-14-410");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/25");  # fixed upstream
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/09");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("apache_mod_proxy_info_leak.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("/tmp/CVE-2011-3368");

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
    exit(0, 'The web server on port ' + port + ' doesn\'t look like an Apache-based httpd');

  # looks like Apache _httpd_
  if ('apache' >< tolower(server) && ( 'coyote' >< tolower(server) || 'tomcat' >< tolower(server)) )
    exit(0, 'The web server on port ' + port + ' doesn\'t look like Apache httpd');
}

pages = make_list('/');

foreach page (pages)
{
  # GET 1324:@target-host/page
  # misconfigured servers reconstruct the URI as http://intended-host@target-host/page
  # instead of responding with an HTTP 400
  url = strcat(unixtime(), ':@', get_host_ip(), page);
  res = http_send_recv3(method:'GET', item:url, version:9, port:port, exit_on_fail:TRUE);

  # the patched server should always send a 400.
  # HTTP 0.9 won't send a status line so the best we can do is check for the default 400 page.
  # Need to skip over pages that respond to valid requests with a 503, since we will rely on a
  # 503 response after making the next request
  if ('<title>400 Bad Request</title>' >!< res[2] && '<title>503 Service Temporarily Unavailable</title>' >!< res[2])
  {
    # GET 1324:@target-host:likely-closed-port/page
    # misconfigured servers reconstruct the URI as http://intended-host@target-host:likely-closed-port/page
    # instead of responding with an HTTP 400
    url = strcat(unixtime(), ':@localhost:', (rand() % 535 + 65000), page);
    res = http_send_recv3(method:'GET', item:url, version:9, port:port, exit_on_fail:TRUE);

    # the patched server should always send a 400. 
    # Again, we won't get a status code via HTTP 0.9 so the best we can do is check for the default
    # 503 page (resulting from trying to connect to a closed port)
    if ('<title>503 Service Temporarily Unavailable</title>' >< res[2])
    {
      if (report_verbosity > 0)
      {
        report =
          '\nNessus verified this by sending the following request :\n\n' +
          chomp(http_last_sent_request()) + '\n';

        if (report_verbosity > 0)
        {
          report +=
            '\nWhich resulted in a non-400 response :\n\n' +
            chomp(res[2]) + '\n';
        }

        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
}
exit(0, 'The web server listening on port '+port+' is likely not affected.');

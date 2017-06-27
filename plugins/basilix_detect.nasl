#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Revised plugin title (12/28/10)

include("compat.inc");

if (description) {
  script_id(14308);
  script_version("$Revision: 1.22 $");
 
  script_name(english:"BasiliX Application Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a webmail application written in PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running BasiliX, a webmail application based on PHP
and IMAP and powered by MySQL." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/projects/basilix/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/09");
 script_cvs_date("$Date: 2015/10/13 15:19:32 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_summary(english:"Checks for the presence of BasiliX");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2004-2015 George A. Theall");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}

#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Search for BasiliX in a couple of different locations.
if (thorough_tests) dirs = list_uniq(make_list("/basilix", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  url = string(dir, "/basilix.php");
  if (port == 443) url = string(url, "?is_ssl=1");

  # Get the page.
  req = string(
    "GET ",  url, " HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Cookie: BSX_TestCookie=yes\r\n",
    "\r\n"
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  if ("BasiliX" >< res) {
    # Search for the version string in a couple of different places.
    #
    # - it's usually in the HTML title element.
    title = strstr(res, "<title>");
    if (title != NULL) {
      title = title - strstr(title,string("\n"));
      pat = "BasiliX (.+)</title>";
      ver = eregmatch(pattern:pat, string:title, icase:TRUE);
      if (ver != NULL) ver = ver[1];
    }
    # - otherwise, look at the "generator" meta tag.
    if (isnull(ver)) {
      generator = strstr(res, '<meta name="generator"');
      if (generator != NULL) {
        generator = generator - strstr(generator, string("\n"));
        pat = 'content="BasiliX (.+)"';
        ver = eregmatch(pattern:pat, string:generator, icase:TRUE);
        if (ver != NULL) ver = ver[1];
      }
    }
    # - last try, older versions include it in the copyright notice.
    if (isnull(ver)) {
      copyright = strstr(res, "BasiliX v");
      if (copyright != NULL) {
        copyright = copyright - strstr(copyright, string("\n"));
        pat = "BasiliX v(.+) -- &copy";
        ver = eregmatch(pattern:pat, string:copyright, icase:TRUE);
        if (ver != NULL) ver = ver[1];
      }
    }

    # Handle reporting
    if (!isnull(ver)) {
      set_kb_item(
        name:string("www/", port, "/basilix"), 
        value:string(ver, " under ", dir)
      );
      set_kb_item(name:"www/basilix", value:TRUE);
      installations[dir] = ver;
      ++installs;
    }

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (installs && !thorough_tests) break;
  }
}


# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    info = string("BasiliX ", ver, " was detected on the remote host under the path ", dir, ".");
  }
  else {
    info = string(
      "Multiple instances of BasiliX were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  security_note(port:port, extra:'\n'+info);
}

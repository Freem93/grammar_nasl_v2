#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19778);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-3049");
  script_bugtraq_id(
    14927, 
    14928, 
    14929, 
    14930
 );
  script_osvdb_id(19670);

  script_name(english:"phpMyFAQ < 1.5.2 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are prone to a
variety of flaws, including remote code execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpMyFAQ that suffers from
arbitrary code execution (if the server is Windows-based), SQL
injection and cross-site scripting attacks, as well as information
disclosure." );
  # https://web.archive.org/web/20120402145856/http://retrogod.altervista.org/phpmyfuck151.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5ae2996");
 script_set_attribute(attribute:"see_also", value:"http://www.phpmyfaq.de/advisory_2005-09-23.php");
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyFAQ 1.5.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/22");
 script_cvs_date("$Date: 2017/04/25 14:31:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpmyfaq:phpmyfaq");
script_end_attributes();

  script_summary(english:"Checks for multiple vulnerabilities in phpMyFAQ < 1.5.2");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
  script_dependencies("phpmyfaq_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpmyfaq");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpmyfaq"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Try to exploit one of the XSS flaws.
  #
  # nb: I know this is lame but there's no way to test the SQL
  #     injection flaw, the remote code execution flaws work only
  #     under Windows, and trying to read the tracking logs will
  #     only work if the site has seen activity recently.
  if (!get_kb_item("www/"+port+"/generic_xss")) {
    # A simple alert.
    xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
    exss = urlencode(str:xss);

    # Try to exploit the flaw.
    r = http_send_recv3(method:"GET", port:port,
      item:string(dir, "/admin/footer.php?", "PMF_CONF[version]=", exss));
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if we see our XSS.
    if (xss >< res) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }

  # Check the version number in case register_globals is off or the 
  # web server itself is vulnerable to cross-site scripting attacks.
  if (ver =~ "^(0\.|1\.([0-4]\.|5\.[01]($|[^0-9])))") {
    w = string(
        "***** Nessus has determined the vulnerability exists on the remote\n",
        "***** host simply by looking at the version number of phpMyFAQ\n",
        "***** installed there.\n");
    security_warning(port:port, extra: w);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}

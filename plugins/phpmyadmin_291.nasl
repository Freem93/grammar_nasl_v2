#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22512);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/02 14:37:08 $");

  script_cve_id("CVE-2006-5116");
  script_bugtraq_id(20253);
  script_osvdb_id(29240, 30140, 30141);

  script_name(english:"phpMyAdmin < 2.9.1 Multiple Vulnerabilities");
  script_summary(english:"Tries to pass in a numeric key in phpMyAdmin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple issues." );
  script_set_attribute(attribute:"description", value:
"The version of phpMyAdmin installed on the remote host allows an
unauthenticated attacker to bypass variable blacklisting in its
globalization routine and destroy, for example, the contents of
session variables." );
  script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_072006.130.html" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Oct/5" );
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2006-5" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 2.9.0.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/06");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/27");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpMyAdmin", "www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php: 1);


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Grab index.php.
  url = string(dir, "/index.php");
  res = http_get_cache(item:url, port:port, exit_on_fail: 1);

  # Don't check if we see an error like the one we'll try to generate.
  if (
    "Fatal error" >< res ||
    "Call to a member function on a non-object in" >< res
  ) exit(0);

  # Try to overwrite $_SESSION via 'libraries/grab_globals.lib.php'.
  # If successful, this will lead to a fatal error later in 
  # 'libraries/common.lib.php'. 
  bound = "bound";
  boundary = string("--", bound);
  postdata = string(
    boundary, "\r\n", 
    'Content-Disposition: form-data; name="_SESSION"; filename="nessus";', "\r\n",
    "Content-Type: text/plain\r\n",
    "\r\n",
    "foo\r\n",

    boundary, "--", "\r\n"
  );
  r = http_send_recv3(method:"POST", item: url, version: 11, port:port,
    exit_on_fail: 1,
    content_type: "multipart/form-data; boundary="+bound,
    data: postdata);
  res = r[2];

  # There's a problem if we see a fatal error.
  if (res && "Call to a member function on a non-object in" >< res) 
    security_warning(port);
  # what to do if (res == NULL) (eg, error display is disable but
  # app is vulnerable)???
}

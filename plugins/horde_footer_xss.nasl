#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18132);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2005-1315");
  script_osvdb_id(15764);

  script_name(english:"Horde Turba Contact Manager common-footer.inc Parent Frame Page Title XSS");
  script_summary(english:"Checks for cross-site scripting vulnerability in Horde common-footer.inc");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a cross-
site scripting attack.");
  script_set_attribute(attribute:"description", value:
"According to its version, the remote installation of Horde fails to
fully sanitize user-supplied input when setting the parent frame's
page title by JavaScript in 'templates/common-footer.inc'.  By
leveraging this flaw, an attacker may be able to inject arbitrary HTML
and script code into a user's browser to be executed in the context of
the affected website, thereby resulting in the theft of session
cookies and similar attacks.");
  script_set_attribute(attribute:"see_also", value:"https://lists.horde.org/archives/announce/2005/000191.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Horde 2.2.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/26");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/22");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:horde_application_framework");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

  script_dependencies("horde_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/horde");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP.");


# Test an install.
install = get_kb_item(string("www/", port, "/horde"));
if (isnull(install)) exit(0, "Horde was not detected on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "^([01]|2\.([01]|2$|2\.[0-7]([^0-9]|$)))")
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}

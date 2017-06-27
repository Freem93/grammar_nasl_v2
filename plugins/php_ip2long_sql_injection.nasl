#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17715);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/25 14:31:38 $");

  script_cve_id("CVE-2006-4023");
  script_osvdb_id(29069);

  script_name(english:"PHP ip2long Function String Validation Weakness");
  script_summary(english:"Checks version of PHP");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that does not properly
validate user strings."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the 'ip2long()' function in the version of
PHP installed on the remote host may incorrectly validate an arbitrary
string and return a valid network IP address."
  );
 # https://web.archive.org/web/20141122094639/http://retrogod.altervista.org/php_ip2long.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f88768a");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/441529/100/100/threaded");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "Settings/PCI_DSS");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("webapp_func.inc");

# Only PCI considers this an issue.
if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

# nb: unfixed.
if (report_verbosity > 0)
{
  report =
    '\n  Version source     : ' + source +
    '\n  Installed version  : ' + version + 
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);

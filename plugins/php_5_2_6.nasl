#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32123);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id(
    "CVE-2007-4850",
    "CVE-2007-6039",
    "CVE-2008-0599",
    #"CVE-2008-0674",         PCRE buffer overflow
    "CVE-2008-1384",
    "CVE-2008-2050",
    "CVE-2008-2051"
  );
  script_bugtraq_id(27413, 28392, 29009);
  script_osvdb_id(43219, 44057, 44906, 44907, 44908, 45304, 45305);
  script_xref(name:"Secunia", value:"30048");

  script_name(english:"PHP < 5.2.6 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is affected by
multiple flaws."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP installed on the remote
host is older than 5.2.6.  Such versions may be affected by the
following issues :

  - A stack-based buffer overflow in FastCGI SAPI.

  - An integer overflow in printf().

  - An security issue arising from improper calculation
    of the length of PATH_TRANSLATED in cgi_main.c.

  - A safe_mode bypass in cURL.

  - Incomplete handling of multibyte chars inside
    escapeshellcmd().

  - Issues in the bundled PCRE fixed by version 7.6."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Mar/285");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/May/102");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/May/106");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_6.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

if (version =~ "^5\.[01]\." || 
    version =~ "^5\.2\.[0-5]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.2.6\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);

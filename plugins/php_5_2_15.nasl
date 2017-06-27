#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51139);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/10/23 20:09:34 $");

  script_cve_id(
    "CVE-2010-3436",
    "CVE-2010-3709",
    "CVE-2010-4150",
    "CVE-2010-4697",
    "CVE-2010-4698",
    "CVE-2011-0752"
  );
  script_bugtraq_id(44718, 44723, 45335, 45952, 46448);
  script_osvdb_id(68597, 69109, 69110, 69660, 70607, 70608, 74728);

  script_name(english:"PHP 5.2 < 5.2.15 Multiple Vulnerabilities");
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
"According to its banner, the version of PHP 5.2 installed on the
remote host is older than 5.2.15.  Such versions may be affected by
several security issues :
  
  - A crash in the zip extract method.

  - A possible double free exists in the imap extension.
    (CVE-2010-4150)

  - An unspecified flaw exists in 'open_basedir'. 
    (CVE-2010-3436)

  - A possible crash could occur in 'mssql_fetch_batch()'.
  
  - A NULL pointer dereference exists in 
    'ZipArchive::getArchiveComment'. (CVE-2010-3709)

  - A crash exists if anti-aliasing steps are invalid.
    (Bug #53492)

  - A crash exists in pdo_firebird getAttribute(). (Bug 
    #53323)

  - A user-after-free vulnerability in the Zend engine when
    a '__set()', '__get()', '__isset()' or '__unset()' 
    method is called can allow for a denial of service 
    attack. (Bug #52879 / CVE-2010-4697)

  - A stack-based buffer overflow exists in the 
    'imagepstext()' function in the GD extension. (Bug 
    #53492 / CVE-2010-4698)
    
  - The extract function does not prevent use of the
    EXTR_OVERWRITE parameter to overwrite the GLOBALS
    superglobal array and the 'this' variable, which
    allows attackers to bypass intended access restrictions.
    (CVE-2011-0752)"
  );

  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_15.php");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.2.15");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.2.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");

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

if (version =~ "^5\.2\.([0-9]|1[0-4])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.2.15\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);

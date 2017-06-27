#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42862);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/16 14:22:05 $");

  script_cve_id(
    "CVE-2009-3557",
    "CVE-2009-3559",
    "CVE-2009-4017",
    "CVE-2009-4018",
    "CVE-2010-1128"
  );
  script_bugtraq_id(36554, 36555, 37079, 37138);
  script_osvdb_id(58188, 60434, 60435, 60436, 60437, 60438, 60451, 63323);
  script_xref(name:"Secunia", value:"37412");

  script_name(english:"PHP 5.3 < 5.3.1 Multiple Vulnerabilities");
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
"According to its banner, the version of PHP 5.3 installed on the
remote host is older than 5.3.1.  Such versions may be affected by
several security issues :

  - Sanity checks are missing in exif processing.

  - It is possible to bypass the 'safe_mode' configuration
    setting using 'tempnam()'.

  - It is possible to bypass the 'open_basedir' 
    configuration setting using 'posix_mkfifo()'.

  - The 'safe_mode_include_dir' configuration setting may
    be ignored. (Bug #50063)

  - Calling 'popen()' with an invalid mode can cause a 
    crash under Windows. (Bug #44683)

  - Provided file uploading is enabled (it is by default),
    an attacker can upload files using a POST request with
    'multipart/form-data' content even if the target script 
    doesn't actually support file uploads per se. By
    supplying a large number (15,000+) of files, an attacker
    could cause the web server to stop responding while it
    processes the file list.

  - 'proc_open()' can bypass 'safe_mode_protected_env_vars'.
    (Bug #49026)

  - An unspecified vulnerability affects the LCG entropy."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/507982/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/releases/5_3_1.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.3.1"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to PHP version 5.3.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

if (version =~ "^5\.3\.0($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.3.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84362);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  script_cve_id(
    "CVE-2015-2325",
    "CVE-2015-2326",
    "CVE-2015-3414",
    "CVE-2015-3415",
    "CVE-2015-3416",
    "CVE-2015-4598",
    "CVE-2015-4642",
    "CVE-2015-4643",
    "CVE-2015-4644"
  );
  script_bugtraq_id(
    74228,
    75174,
    75175,
    75244,
    75290,
    75291,
    75292
  );
  script_osvdb_id(
    117588,
    119870,
    119871,
    120909,
    120943,
    120944,
    122126,
    123148,
    123160
  );

  script_name(english:"PHP 5.4.x < 5.4.42 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP 5.4.x running on the
remote web server is prior to 5.4.42. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple heap buffer overflow conditions exist in the
    bundled Perl-Compatible Regular Expression (PCRE)
    library due to improper validation of user-supplied
    input to the compile_branch() and pcre_compile2()
    functions. A remote attacker can exploit these
    conditions to cause a heap-based buffer overflow,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2015-2325,
    CVE-2015-2326)

  - A denial of service vulnerability exists in the bundled
    SQLite component due to improper handling of quotes
    in collation sequence names. A remote attacker can
    exploit this to cause uninitialized memory access,
    resulting in denial of service condition.
    (CVE-2015-3414)

  - A denial of service vulnerability exists in the bundled
    SQLite component due to an improper implementation of
    comparison operators in the sqlite3VdbeExec() function
    in vdbe.c. A remote attacker can exploit this to cause
    an invalid free operation, resulting in a denial of
    service condition. (CVE-2015-3415)

  - A denial of service vulnerability exists in the bundled
    SQLite component due to improper handling of precision
    and width values during floating-point conversions in
    the sqlite3VXPrintf() function in printf.c. A remote
    attacker can exploit this to cause a stack-based buffer
    overflow, resulting in a denial of service condition or
    the execution of arbitrary code. (CVE-2015-3416)

  - A security bypass vulnerability exists due to a failure
    in multiple extensions to check for NULL bytes in a path
    when processing or reading a file. A remote attacker can
    exploit this, by combining the '\0' character with a
    safe file extension, to bypass access restrictions.
    (CVE-2015-4598)

  - An arbitrary command injection vulnerability exists due
    to a flaw in the php_escape_shell_arg() function in
    exec.c. A remote attacker can exploit this, via the
    escapeshellarg() PHP method, to inject arbitrary
    operating system commands. (CVE-2015-4642)

  - A heap buffer overflow condition exists in the
    ftp_genlist() function in ftp.c. due to improper
    validation of user-supplied input. A remote attacker
    can exploit this to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2015-4643)
    
  - A denial of service vulnerability exists due to a NULL
    pointer dereference flaw in the build_tablename()
    function in pgsql.c. An authenticated, remote attacker
    can exploit this to cause an application crash.
    (CVE-2015-4644)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.4.42");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.4.42 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.4)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.4\.") audit(AUDIT_NOT_DETECT, "PHP version 5.4.x", port);

if (version =~ "^5\.4\.([0-9]|[1-3][0-9]|4[01])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.4.42' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);

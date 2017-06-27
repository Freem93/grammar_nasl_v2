#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55925);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id(
    "CVE-2011-1148",
    "CVE-2011-1657",
    "CVE-2011-1938",
    "CVE-2011-2202",
    "CVE-2011-2483",
    "CVE-2011-3182",
    "CVE-2011-3267",
    "CVE-2011-3268"
  );
  script_bugtraq_id(
    46843,
    47950,
    48259,
    49241,
    49249,
    49252
  );
  script_osvdb_id(
    72644,
    73113,
    73218,
    74738,
    74739,
    74742,
    74743,
    75200,
    126477
  );
  script_xref(name:"EDB-ID", value:"17318");
  script_xref(name:"EDB-ID", value:"17486");

  script_name(english:"PHP 5.3 < 5.3.7 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP 5.3.x running on the
remote host is prior to 5.3.7. It is, therefore, affected by the
following vulnerabilities :

  - A use-after-free vulnerability in substr_replace().
   (CVE-2011-1148)

  - A stack-based buffer overflow in socket_connect().
   (CVE-2011-1938)

  - A code execution vulnerability in ZipArchive::addGlob().
    (CVE-2011-1657)

  - crypt_blowfish was updated to 1.2. (CVE-2011-2483)

  - Multiple NULL pointer dereferences. (CVE-2011-3182)

  - An unspecified crash in error_log(). (CVE-2011-3267)

  - A buffer overflow in crypt(). (CVE-2011-3268)

  - A flaw exists in the php_win32_get_random_bytes()
    function when passing MCRYPT_DEV_URANDOM as source to
    mcrypt_create_iv(). A remote attacker can exploit this
    to cause a denial of service condition. (VulnDB 126477)");
  script_set_attribute(attribute:"see_also", value:"http://securityreason.com/achievement_securityalert/101");
  script_set_attribute(attribute:"see_also", value:"http://securityreason.com/exploitalert/10738");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=54238");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=54681");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=54939");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_3_7.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP 5.3.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

if (version =~ '^5(\\.3)?$') exit(1, "The banner for PHP on port "+port+" - "+source+" - is not granular enough to make a determination.");

if (version =~ "^5\.3\.[0-6]($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.3.7\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);

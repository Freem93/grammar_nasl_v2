#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71426);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:22:05 $");

  script_cve_id("CVE-2013-4073", "CVE-2013-6420");
  script_bugtraq_id(60843, 64225);
  script_osvdb_id(100979, 94628);
  script_xref(name:"EDB-ID", value:"30395");

  script_name(english:"PHP 5.3.x < 5.3.28 Multiple OpenSSL Vulnerabilities");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is potentially
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP installed on the remote
host is 5.3.x prior to 5.3.28.  It is, therefore, potentially affected
by the following vulnerabilities :

  - A flaw exists in the PHP OpenSSL extension's hostname
    identity check when handling certificates that contain
    hostnames with NULL bytes. An attacker could potentially
    exploit this flaw to conduct man-in-the-middle attacks
    to spoof SSL servers. Note that to exploit this issue,
    an attacker would need to obtain a carefully-crafted
    certificate signed by an authority that the client
    trusts. (CVE-2013-4073)

  - A memory corruption flaw exists in the way the
    openssl_x509_parse() function of the PHP OpenSSL
    extension parsed X.509 certificates. A remote attacker
    could use this flaw to provide a malicious, self-signed
    certificate or a certificate signed by a trusted
    authority to a PHP application using the aforementioned
    function. This could cause the application to crash or
    possibly allow the attacker to execute arbitrary code
    with the privileges of the user running the PHP
    interpreter. (CVE-2013-6420)

Note that this plugin does not attempt to exploit these vulnerabilities,
but instead relies only on PHP's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Dec/96");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1036830");
  # http://git.php.net/?p=php-src.git;a=commit;h=2874696a5a8d46639d261571f915c493cd875897
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6ec9ef9");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.3.28");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.3.28 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
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
if (version =~ "^5(\.3)?$") exit(1, "The banner from the PHP install associated with port "+port+" - "+version+" - is not granular enough to make a determination.");
if (version !~ "^5\.3\.") audit(AUDIT_NOT_DETECT, "PHP version 5.3.x", port);

if (version =~ "^5\.3\.([0-9]|[1][0-9]|2[0-7])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version+
      '\n  Fixed version     : 5.3.28\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);

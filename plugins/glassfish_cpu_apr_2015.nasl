#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82902);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id(
    "CVE-2013-4545",
    "CVE-2014-1568",
    "CVE-2014-3566"
  );
  script_bugtraq_id(
    63776,
    70116,
    70574
  );
  script_osvdb_id(
    99972,
    112036,
    113251
  );
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"CERT", value:"772676");

  script_name(english:"Oracle GlassFish Server Multiple Vulnerabilities (April 2015 CPU) (POODLE)");
  script_summary(english:"Checks the version of Oracle GlassFish.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of GlassFish Server running on the remote host is affected
by multiple vulnerabilities :

  - A flaw exists in the bundled cURL and libcurl packages.
    The certificate CN and SAN name field verification
    (CURLOPT_SSL_VERIFYHOST) is disabled when the digital
    signature verification (CURLOPT_SSL_VERIFYPEER) is
    disabled. This allows a man-in-the-middle attacker to
    spoof SSL servers via an arbitrary valid certificate.
    (CVE-2013-4545)

  - A flaw exists in the bundled Network Security Services
    (NSS) library due to improper parsing of ASN.1 values in
    X.509 certificates. This allows a man-in-the-middle 
    attacker to spoof RSA signatures via a crafted
    certificate. (CVE-2014-1568)

  - A man-in-the-middle (MitM) information disclosure
    vulnerability known as POODLE. The vulnerability is due
    to the way SSL 3.0 handles padding bytes when decrypting
    messages encrypted using block ciphers in cipher block
    chaining (CBC) mode. MitM attackers can decrypt a
    selected byte of a cipher text in as few as 256 tries if
    they are able to force a victim application to
    repeatedly send the same data over newly created SSL 3.0
    connections. (CVE-2014-3566)");
  script_set_attribute(attribute:"solution", value:
"Upgrade to GlassFish Server 2.1.1.25 / 3.0.1.11 / 3.1.2.11 or later as
referenced in the April 2015 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15c09d3d");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("glassfish_detect.nasl");
  script_require_keys("www/glassfish");
  script_require_ports("Services/www", 80, 4848, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

get_kb_item_or_exit("www/glassfish");

# By default, GlassFish listens on port 8080.
port = get_http_port(default:8080);

# Get the version number out of the KB.
ver = get_kb_item_or_exit("www/" + port + "/glassfish/version");
banner = get_kb_item_or_exit("www/" + port + "/glassfish/source");
pristine = get_kb_item_or_exit("www/" + port + "/glassfish/version/pristine");

# Set appropriate fixed versions.
if (ver =~ "^2\.1\.1") fix = "2.1.1.25";
else if (ver =~ "^3\.0\.1") fix = "3.0.1.11";
else if (ver =~ "^3\.1\.2") fix = "3.1.2.11";
else fix = NULL;

if (!isnull(fix) && ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + pristine +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Oracle GlassFish", port, pristine);

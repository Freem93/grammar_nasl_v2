#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76591);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id(
    "CVE-2013-1739",
    "CVE-2013-1740",
    "CVE-2013-1741",
    "CVE-2013-5605",
    "CVE-2013-5606",
    "CVE-2013-5855",
    "CVE-2014-1490",
    "CVE-2014-1491",
    "CVE-2014-1492"
  );
  script_bugtraq_id(
    62966,
    63736,
    63737,
    63738,
    64944,
    65332,
    65335,
    65600,
    66356
  );
  script_osvdb_id(
    98402,
    99746,
    99747,
    99748,
    102170,
    102876,
    102877,
    103373,
    104708
  );

  script_name(english:"Oracle GlassFish Server Multiple Vulnerabilities (July 2014 CPU)");
  script_summary(english:"Checks the version of Oracle GlassFish.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of GlassFish Server running on the remote host is affected
by multiple vulnerabilities in the following components :

  - The implementation of Network Security Services (NSS)
    does not ensure that data structures are initialized,
    which could result in a denial of service or disclosure
    of sensitive information. (CVE-2013-1739)

  - The implementation of Network Security Services (NSS)
    does not properly handle the TLS False Start feature
    and could allow man-in-the-middle attacks.
    (CVE-2013-1740)

  - Network Security Services (NSS) contains an integer
    overflow flaw that allows remote attackers to cause a
    denial of service. (CVE-2013-1741)

  - An error exists in the 'Null_Cipher' function in the
    file 'ssl/ssl3con.c' related to handling invalid
    handshake packets that could allow arbitrary code
    execution. (CVE-2013-5605)

  - An error exists in the 'CERT_VerifyCert' function in
    the file 'lib/certhigh/certvfy.c' that could allow
    invalid certificates to be treated as valid.
    (CVE-2013-5606)

  - Oracle Mojarra contains a cross-site scripting
    vulnerability due to improperly sanitized
    user-supplied input. This allows an attacker to
    execute arbitrary script code within the context of
    the affected site. (CVE-2013-5855)

  - Network Security Services (NSS) contains a race
    condition in libssl that occurs during session ticket 
    processing. A remote attacker can exploit this flaw
    to cause a denial of service. (CVE-2014-1490)

  - Network Security Services (NSS) does not properly
    restrict public values in Diffie-Hellman key exchanges,
    allowing a remote attacker to bypass cryptographic
    protection mechanisms. (CVE-2014-1491)

  - An issue exists in the Network Security (NSS) library
    due to improper handling of IDNA domain prefixes for
    wildcard certificates. This issue allows man-in-
    the-middle attacks. (CVE-2014-1492)");
  script_set_attribute(attribute:"solution", value:"Upgrade to GlassFish Server 2.1.1.24 / 3.0.1.9 / 3.1.2.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  # http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7de2f8eb");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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
if (ver =~ "^2\.1\.1") fix = "2.1.1.24";
else if (ver =~ "^3\.0\.1") fix = "3.0.1.9";
else if (ver =~ "^3\.1\.2") fix = "3.1.2.9";
else fix = NULL;

if (!isnull(fix) && ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

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

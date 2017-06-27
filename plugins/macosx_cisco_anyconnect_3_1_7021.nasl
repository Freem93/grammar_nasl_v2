#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82271);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/07 18:00:11 $");

  script_cve_id(
    "CVE-2014-3570",
    "CVE-2014-3571",
    "CVE-2014-8275",
    "CVE-2015-0204",
    "CVE-2015-0206"
  );
  script_bugtraq_id(71935, 71936, 71937, 71939, 71940);
  script_osvdb_id(116791, 116792, 116793, 116794, 116796);
  script_xref(name:"CERT", value:"243585");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus42726");

  script_name(english:"Mac OS X : Cisco AnyConnect Secure Mobility Client < 3.1(7021) <= 4.0(48) Multiple Vulnerabilities (FREAK)"); 
  script_summary(english:"Checks the version of the Cisco AnyConnect client.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Cisco AnyConnect Secure
Mobility Client installed that is prior to 3.1.7021.0, or else it is a
version equal or prior to 4.0.0048.0. It is, therefore, affected by
multiple vulnerabilities in the OpenSSL library :

  - The BIGNUM squaring (BN_sqr) implementation does not
    properly calculate the square of a BIGNUM value. This
    allows remote attackers to defeat cryptographic
    protection mechanisms. (CVE-2014-3570)

  - A NULL pointer dereference flaw exists with
    dtls1_get_record when handling DTLS messages. A remote
    attacker, using a specially crafted DTLS message, can
    cause a denial of service. (CVE-2014-3571)

  - A flaw exists when accepting non-DER variations of
    certificate signature algorithms and signature encodings
    due to a lack of enforcement of matches between signed
    and unsigned portions. A remote attacker, by including
    crafted data within a certificate's unsigned portion,
    can bypass fingerprint-based certificate-blacklist
    protection mechanisms. (CVE-2014-8275)

  - A security feature bypass vulnerability, known as FREAK
    (Factoring attack on RSA-EXPORT Keys), exists due to the
    support of weak EXPORT_RSA cipher suites with keys less
    than or equal to 512 bits. A man-in-the-middle attacker
    may be able to downgrade the SSL/TLS connection to use
    EXPORT_RSA cipher suites which can be factored in a
    short amount of time, allowing the attacker to intercept
    and decrypt the traffic. (CVE-2015-0204)

  - A memory leak occurs in dtls1_buffer_record
    when handling a saturation of DTLS records containing
    the same number sequence but for the next epoch. This
    allows a remote attacker to cause a denial of service.
    (CVE-2015-0206)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150310-ssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd646a4f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco AnyConnect Secure Mobility Client 3.1(7021) or
later, or refer to the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("macosx_cisco_anyconnect_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("Host/MacOSX/Version");

appname = "Cisco AnyConnect Secure Mobility Client";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
path = install['path'];
ver  = install['version'];

fix_display = NULL;

if (ver =~ "^([0-2]|3\.[01])\." && ver_compare(ver:ver, fix:"3.1.7021", strict:FALSE) == -1)
  fix_display = '3.1.7021 (3.1(7021))';
else if (ver =~ "^4\.0\." && ver_compare(ver:ver, fix:"4.0.00048", strict:FALSE) <= 0)
  fix_display = 'Refer to the vendor for a fix.';

if (isnull(fix_display))
  audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);

if (report_verbosity > 0)
{
  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix_display +
    '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);

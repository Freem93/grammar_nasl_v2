#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81406);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id(
    "CVE-2014-3570",
    "CVE-2014-3571",
    "CVE-2014-3572",
    "CVE-2014-8275",
    "CVE-2015-0204",
    "CVE-2015-0205",
    "CVE-2015-0206"
  );
  script_bugtraq_id(
    71935,
    71936,
    71937,
    71939,
    71940,
    71941,
    71942
  );
  script_osvdb_id(
    116790,
    116791,
    116792,
    116793,
    116794,
    116795,
    116796
  );

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory12.asc (FREAK)");
  script_summary(english:"Checks the version of the OpenSSL packages and iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSL installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote AIX host is affected by
the following vulnerabilities :

  - The BIGNUM squaring (BN_sqr) implementation does not
    properly calculate the square of a BIGNUM value. This
    allows remote attackers to defeat cryptographic
    protection mechanisms. (CVE-2014-3570)

  - A NULL pointer dereference flaw exists in the
    dtls1_get_record() function when handling DTLS messages.
    A remote attacker, using a specially crafted DTLS
    message, can cause a denial of service. (CVE-2014-3571)

  - A flaw exists with ECDH handshakes when using an ECDSA
    certificate without a ServerKeyExchange message. This
    allows a remote attacker to trigger a loss of forward
    secrecy from the ciphersuite. (CVE-2014-3572)

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

  - A flaw exists when accepting DH certificates for client
    authentication without the CertificateVerify message.
    This allows a remote attacker to authenticate to the
    service without a private key. (CVE-2015-0205)

  - A memory leak occurs in dtls1_buffer_record when
    handling a saturation of DTLS records containing the
    same number sequence but for the next epoch. This allows
    a remote attacker to cause a denial of service.
    (CVE-2015-0206)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory12.asc");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/marketing/iwm/iwm/web/preLogin.do?source=aixbp");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/18");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

oslevel = get_kb_item("Host/AIX/version");
if (isnull(oslevel)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
if ( oslevel != "AIX-5.3" && oslevel != "AIX-6.1" && oslevel != "AIX-7.1" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.3 / 6.1 / 7.1", oslevel);
}

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

#0.9.8.2503
if (aix_check_ifix(release:"5.3", patch:"(IV69033s9b|IV71446m9b)", package:"openssl.base", minfilesetver:"0.0.0.0", maxfilesetver:"0.9.8.2504") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"(IV69033s9b|IV71446m9b)", package:"openssl.base", minfilesetver:"0.0.0.0", maxfilesetver:"0.9.8.2504") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"(IV69033s9b|IV71446m9b)", package:"openssl.base", minfilesetver:"0.0.0.0", maxfilesetver:"0.9.8.2504") < 0) flag++;

#1.0.1.512
if (aix_check_ifix(release:"5.3", patch:"(IV69033s9a|IV71446m9a)", package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.513") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"(IV69033s9a|IV71446m9a)", package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.513") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"(IV69033s9a|IV71446m9a)", package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.513") < 0) flag++;

#12.9.8.2503
if (aix_check_ifix(release:"5.3", patch:"(IV69033s9c|IV71446m9c)", package:"openssl.base", minfilesetver:"12.0.0.0", maxfilesetver:"12.9.8.2504") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"(IV69033s9c|IV71446m9c)", package:"openssl.base", minfilesetver:"12.0.0.0", maxfilesetver:"12.9.8.2504") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"(IV69033s9c|IV71446m9c)", package:"openssl.base", minfilesetver:"12.0.0.0", maxfilesetver:"12.9.8.2504") < 0) flag++;

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_extra);
  else security_warning(0);
  exit(0);
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl.base");
}

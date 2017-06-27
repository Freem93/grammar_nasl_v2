#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory openssl_advisory4.asc.
#

include("compat.inc");

if (description)
{
  script_id(73562);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id(
    "CVE-2012-0884",
    "CVE-2012-1165",
    "CVE-2012-2110",
    "CVE-2012-2131",
    "CVE-2012-2333"
  );
  script_bugtraq_id(52428, 52764, 53158, 53212, 53476);
  script_osvdb_id(80039, 80040, 81223, 81810, 82110);

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory4.asc");
  script_summary(english:"Checks the version of the openssl packages");

  script_set_attribute(attribute:"synopsis", value:"The remote AIX host is running a vulnerable version of OpenSSL.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL running on the remote host is affected by the
following vulnerabilities :

  - The implementation of Cryptographic Message Syntax (CMS)
    and PKCS #7 in OpenSSL does not properly restrict
    certain oracle behavior, which makes it easier for
    context-dependent attackers to decrypt data via a
    Million Message Attack (MMA) adaptive chosen ciphertext
    attack. (CVE-2012-0884)

  - The mime_param_cmp function in crypto/asn1/asn_mime.c in
    OpenSSL allows remote attackers to cause a denial of
    service (NULL pointer dereference and application crash)
    via a crafted S/MIME message, a different vulnerability
    than CVE-2006-7250. (CVE-2012-1165)

  - The asn1_d2i_read_bio function in crypto/asn1/a_d2i_fp.c
    in OpenSSL does not properly interpret integer data,
    which allows remote attackers to conduct buffer overflow
    attacks, and cause a denial of service (memory
    corruption) or possibly have unspecified other impact,
    via crafted DER data, as demonstrated by an X.509
    certificate or an RSA public key. (CVE-2012-2110)

  - Multiple integer signedness errors in
    crypto/buffer/buffer.c in OpenSSL allow remote attackers
    to conduct buffer overflow attacks, and cause a denial
    of service (memory corruption) or possibly have
    unspecified other impact, via crafted DER data, as
    demonstrated by an X.509 certificate or an RSA public
    key. NOTE: this vulnerability exists because of an
    incomplete fix for CVE-2012-2110. (CVE-2012-2131)

  - Integer underflow in OpenSSL when TLS 1.1, TLS 1.2, or
    DTLS is used with CBC encryption, allows remote
    attackers to cause a denial of service (buffer over-
    read) or possibly have unspecified other impact via a
    crafted TLS packet that is not properly handled during a
    certain explicit IV calculation. (CVE-2012-2333)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory4.asc");
  script_set_attribute(attribute:"see_also", value:"https://www14.software.ibm.com/webapp/iwm/web/preLogin.do?source=aixbp");
  script_set_attribute(attribute:"solution", value:
"A fix is available, and it can be downloaded from the AIX website.

To extract the fixes from the tar file :

  zcat openssl-0.9.8.1802.tar.Z | tar xvf -
  or
  zcat openssl-fips-12.9.8.1802.tar.Z | tar xvf -

IMPORTANT : If possible, it is recommended that a mksysb backup of
the system be created.  Verify it is both bootable and readable
before proceeding.

To preview the fix installation :

  installp -apYd . openssl

To install the fix package :

  installp -aXYd . openssl");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/16");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
oslevel = get_kb_item_or_exit("Host/AIX/version");
if ( oslevel != "AIX-5.3" && oslevel != "AIX-6.1" && oslevel != "AIX-7.1" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.3 / 6.1 / 7.1", oslevel);
}
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;

if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.1801", fixpackagever:"0.9.8.1802") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.1801", fixpackagever:"0.9.8.1802") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.1801", fixpackagever:"0.9.8.1802") > 0) flag++;
if (aix_check_package(release:"5.3", package:"openssl-fips.base", minpackagever:"0.0.0.0", maxpackagever:"12.9.8.1801", fixpackagever:"12.9.8.1802") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl-fips.base", minpackagever:"0.0.0.0", maxpackagever:"12.9.8.1801", fixpackagever:"12.9.8.1802") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl-fips.base", minpackagever:"0.0.0.0", maxpackagever:"12.9.8.1801", fixpackagever:"12.9.8.1802") > 0) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : aix_report_get()
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl.base / openssl-fips.base");
}

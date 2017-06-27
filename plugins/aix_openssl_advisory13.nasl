#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory openssl_advisory13.asc.
#

include("compat.inc");

if (description)
{
  script_id(82900);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id(
    "CVE-2015-0209",
    "CVE-2015-0286",
    "CVE-2015-0287",
    "CVE-2015-0288",
    "CVE-2015-0289",
    "CVE-2015-0292",
    "CVE-2015-0293"
  );
  script_bugtraq_id(
    73225,
    73227,
    73228,
    73231,
    73232,
    73237,
    73239
  );
  script_osvdb_id(
    118817,
    119328,
    119743,
    119755,
    119756,
    119757,
    119761
  );

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory13.asc");
  script_summary(english:"Checks the version of the OpenSSL packages and iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSL installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote AIX host is affected by
the following vulnerabilities :

  - A use-after-free condition exists in the
    d2i_ECPrivateKey() function due to improper processing
    of malformed EC private key files during import. A
    remote attacker can exploit this to dereference or free
    already freed memory, resulting in a denial of service
    or other unspecified impact. (CVE-2015-0209)

  - An invalid read flaw exists in the ASN1_TYPE_cmp()
    function due to improperly performed boolean-type
    comparisons. A remote attacker can exploit this, via a
    crafted X.509 certificate to an endpoint that uses the
    certificate-verification feature, to cause an invalid
    read operation, resulting in a denial of service.
    (CVE-2015-0286)

  - A flaw exists in the ASN1_item_ex_d2i() function due to
    a failure to reinitialize 'CHOICE' and 'ADB' data
    structures when reusing a structure in ASN.1 parsing.
    This allows a remote attacker to cause an invalid write
    operation and memory corruption, resulting in a denial
    of service. (CVE-2015-0287)

  - A NULL pointer dereference flaw exists in the
    X509_to_X509_REQ() function due to improper processing
    of certificate keys. This allows a remote attacker, via
    a crafted X.509 certificate, to cause a denial of
    service. (CVE-2015-0288)

  - A NULL pointer dereference flaw exists in the PKCS#7
    parsing code due to incorrect handling of missing outer
    ContentInfo. This allows a remote attacker, using an
    application that processes arbitrary PKCS#7 data and
    providing malformed data with ASN.1 encoding, to cause
    a denial of service. (CVE-2015-0289)

  - An integer underflow condition exists in the
    EVP_DecodeUpdate() function due to improper validation
    of base64 encoded input when decoding. This allows a
    remote attacker, using maliciously crafted base64 data,
    to cause a segmentation fault or memory corruption,
    resulting in a denial of service or possibly the
    execution of arbitrary code. (CVE-2015-0292)

  - A flaw exists in servers that both support SSLv2 and
    enable export cipher suites due to improper
    implementation of SSLv2. A remote attacker can exploit
    this, via a crafted CLIENT-MASTER-KEY message, to cause
    a denial of service. (CVE-2015-0293)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory13.asc");
  script_set_attribute(attribute:"see_also", value:"https://www14.software.ibm.com/webapp/iwm/web/preLogin.do?source=aixbp");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the AIX website.

IMPORTANT : If possible, it is recommended that a mksysb backup of the
system be created. Verify that it is both bootable and readable before
proceeding.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/20");

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
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

#0.9.8.2503
if (aix_check_ifix(release:"5.3", patch:"IV71446m9b", package:"openssl.base", minfilesetver:"0.0.0.0", maxfilesetver:"0.9.8.2504") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"IV71446m9b", package:"openssl.base", minfilesetver:"0.0.0.0", maxfilesetver:"0.9.8.2504") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"IV71446m9b", package:"openssl.base", minfilesetver:"0.0.0.0", maxfilesetver:"0.9.8.2504") < 0) flag++;

#1.0.1.512
if (aix_check_ifix(release:"5.3", patch:"IV71446m9a", package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.513") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"IV71446m9a", package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.513") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"IV71446m9a", package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.513") < 0) flag++;

#12.9.8.2503
if (aix_check_ifix(release:"5.3", patch:"IV71446m9c", package:"openssl.base", minfilesetver:"12.0.0.0", maxfilesetver:"12.9.8.2504") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"IV71446m9c", package:"openssl.base", minfilesetver:"12.0.0.0", maxfilesetver:"12.9.8.2504") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"IV71446m9c", package:"openssl.base", minfilesetver:"12.0.0.0", maxfilesetver:"12.9.8.2504") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

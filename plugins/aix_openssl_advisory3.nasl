#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory openssl_advisory3.asc.
#

include("compat.inc");

if (description)
{
  script_id(73561);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id(
    "CVE-2011-4108",
    "CVE-2011-4109",
    "CVE-2011-4576",
    "CVE-2011-4619",
    "CVE-2012-0050"
  );
  script_bugtraq_id(51281, 51563);
  script_osvdb_id(78186, 78187, 78188, 78190, 78320);
  script_xref(name:"CERT", value:"737740");

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory3.asc");
  script_summary(english:"Checks the version of the openssl packages");

  script_set_attribute(attribute:"synopsis", value:"The remote AIX host is running a vulnerable version of OpenSSL.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL running on the remote host is affected by the
following vulnerabilities :

  - The DTLS implementation in OpenSSL before 0.9.8s and 1.x
    before 1.0.0f performs a MAC check only if certain
    padding is valid, which makes it easier for remote
    attackers to recover plaintext via a padding oracle
    attack. (CVE-2011-4108)

  - Double free vulnerability in OpenSSL 0.9.8 before
    0.9.8s, when X509_V_FLAG_POLICY_CHECK is enabled, allows
    remote attackers to have an unspecified impact by
    triggering failure of a policy check. (CVE-2011-4109)

  - The SSL 3.0 implementation in OpenSSL before 0.9.8s and
    1.x before 1.0.0f does not properly initialize data
    structures for block cipher padding, which might allow
    remote attackers to obtain sensitive information by
    decrypting the padding data sent by an SSL peer.
    (CVE-2011-4576)

  - The Server Gated Cryptography (SGC) implementation in
    OpenSSL before 0.9.8s and 1.x before 1.0.0f does not
    properly handle handshake restarts, which allows remote
    attackers to cause a denial of service via unspecified
    vectors. (CVE-2011-4619)

  - OpenSSL 0.9.8s and 1.0.0f does not properly support DTLS
    applications, which allows remote attackers to cause a
    denial of service via unspecified vectors. NOTE: this
    vulnerability exists because of an incorrect fix for
    CVE-2011-4108. (CVE-2012-0050)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory3.asc");
  script_set_attribute(attribute:"see_also", value:"https://www14.software.ibm.com/webapp/iwm/web/preLogin.do?source=aixbp");
  script_set_attribute(attribute:"solution", value:
"A fix is available, and it can be downloaded from the AIX website.

To extract the fixes from the tar file :

  zcat openssl.0.9.8.1801.tar.Z | tar xvf -
  or
  zcat openssl-fips.12.9.8.1801.tar.Z | tar xvf -
  or
  zcat openssl.0.9.8.809.tar.Z | tar xvf -

IMPORTANT : If possible, it is recommended that a mksysb backup of
the system be created.  Verify it is both bootable and readable
before proceeding.

To preview the fix installation :

  installp -apYd . openssl

To install the fix package :

  installp -aXYd . openssl");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/21");
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
if ( oslevel != "AIX-5.2" && oslevel != "AIX-5.3" && oslevel != "AIX-6.1" && oslevel != "AIX-7.1" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.2 / 5.3 / 6.1 / 7.1", oslevel);
}
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;

if (aix_check_package(release:"5.2", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.808", fixpackagever:"0.9.8.809") > 0) flag++;
if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.1800", fixpackagever:"0.9.8.1801") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.1800", fixpackagever:"0.9.8.1801") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.1800", fixpackagever:"0.9.8.1801") > 0) flag++;
if (aix_check_package(release:"5.3", package:"openssl-fips.base", minpackagever:"0.0.0.0", maxpackagever:"12.9.8.1800", fixpackagever:"12.9.8.1801") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl-fips.base", minpackagever:"0.0.0.0", maxpackagever:"12.9.8.1800", fixpackagever:"12.9.8.1801") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl-fips.base", minpackagever:"0.0.0.0", maxpackagever:"12.9.8.1800", fixpackagever:"12.9.8.1801") > 0) flag++;

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

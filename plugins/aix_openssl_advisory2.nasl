#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory openssl_advisory2.asc.
#

include("compat.inc");

if (description)
{
  script_id(73560);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/08/29 13:57:36 $");

  script_cve_id("CVE-2010-3864", "CVE-2010-4180", "CVE-2011-0014");
  script_bugtraq_id(44884, 45164, 46264);
  script_osvdb_id(69265, 69565, 70847);

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory2.asc");
  script_summary(english:"Checks the version of the openssl packages");

  script_set_attribute(attribute:"synopsis", value:"The remote AIX host is running a vulnerable version of OpenSSL.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL running on the remote host is affected by the
following vulnerabilities :

  - ssl/t1_lib.c in OpenSSL 0.9.8h through 0.9.8q and 1.0.0
    through 1.0.0c allows remote attackers to cause a denial
    of service (crash), and possibly obtain sensitive
    information in applications that use OpenSSL, via a
    malformed ClientHello handshake message that triggers an
    out-of-bounds memory access, aka 'OCSP stapling
    vulnerability.' (CVE-2011-0014)

  - Multiple race conditions in ssl/t1_lib.c in OpenSSL
    0.9.8f through 0.9.8o, 1.0.0, and 1.0.0a, when multi-
    threading and internal caching are enabled on a TLS
    server, might allow remote attackers to execute
    arbitrary code via client data that triggers a heap-
    based buffer overflow, related to (1) the TLS server
    name extension and (2) elliptic curve cryptography.
    (CVE-2010-3864)

  - OpenSSL before 0.9.8q, and 1.0.x before 1.0.0c, when
    SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG is enabled, does
    not properly prevent modification of the ciphersuite in
    the session cache, which allows remote attackers to
    force the downgrade to an unintended cipher via vectors
    involving sniffing network traffic to discover a session
    identifier. (CVE-2010-4180)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory2.asc");
  script_set_attribute(attribute:"see_also", value:"https://www14.software.ibm.com/webapp/iwm/web/preLogin.do?source=aixbp");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20110208.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20101116.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20101116.txt");
  script_set_attribute(attribute:"solution", value:
"A fix is available, and it can be downloaded from the AIX website.

To extract the fixes from the tar file :

  zcat openssl.0.9.8.1302.tar.Z | tar xvf -
  or
  zcat openssl-fips.12.9.8.1302.tar.Z | tar xvf -
  or
  zcat openssl.0.9.8.808.tar.Z | tar xvf -

IMPORTANT : If possible, it is recommended that a mksysb backup of
the system be created.  Verify it is both bootable and readable
before proceeding.

To preview the fix installation :

  installp -apYd . openssl

To install the fix package :

  installp -aXYd . openssl");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/04");
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

if (aix_check_package(release:"5.2", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.807", fixpackagever:"0.9.8.808") > 0) flag++;
if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.1301", fixpackagever:"0.9.8.1302") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.1301", fixpackagever:"0.9.8.1302") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.1301", fixpackagever:"0.9.8.1302") > 0) flag++;
if (aix_check_package(release:"5.3", package:"openssl-fips.base", minpackagever:"0.0.0.0", maxpackagever:"12.9.8.1301", fixpackagever:"12.9.8.1302") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl-fips.base", minpackagever:"0.0.0.0", maxpackagever:"12.9.8.1301", fixpackagever:"12.9.8.1302") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl-fips.base", minpackagever:"0.0.0.0", maxpackagever:"12.9.8.1301", fixpackagever:"12.9.8.1302") > 0) flag++;

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

#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory openssl_advisory6.asc.
#

include("compat.inc");

if (description)
{
  script_id(73564);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id("CVE-2013-4353", "CVE-2013-6449", "CVE-2013-6450");
  script_bugtraq_id(64530, 64618, 64691);
  script_osvdb_id(101347, 101597, 101843);

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory6.asc");
  script_summary(english:"Checks the version of the openssl packages");

  script_set_attribute(attribute:"synopsis", value:"The remote AIX host is running a vulnerable version of OpenSSL.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL running on the remote host is affected by the
following vulnerabilities :

  - A carefully crafted invalid TLS handshake could crash
    OpenSSL with a NULL pointer exception. A malicious
    server could use this flaw to crash a connecting client.
    This issue only affected OpenSSL 1.0.1 versions.
    (CVE-2013-4353)

  - A flaw in DTLS handling can cause an application using
    OpenSSL and DTLS to crash. This is not a vulnerability
    for OpenSSL prior to 1.0.0. OpenSSL is vulnerable to a
    denial of service, caused by the failure to properly
    maintain data structures for digest and encryption
    contexts by the DTLS retransmission implementation. A
    remote attacker could exploit this vulnerability to
    cause the daemon to crash. (CVE-2013-6450)

  - A flaw in OpenSSL can cause an application using
    OpenSSL to crash when using TLS version 1.2. This issue
    only affected OpenSSL 1.0.1 versions. OpenSSL is
    vulnerable to a denial of service, caused by an error in
    the ssl_get_algorithm2 function. A remote attacker could
    exploit this vulnerability using specially crafted
    traffic from a TLS 1.2 client to cause the daemon to
    crash. (CVE-2013-6449)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory6.asc");
  script_set_attribute(attribute:"see_also", value:"https://www14.software.ibm.com/webapp/iwm/web/preLogin.do?source=aixbp");
  script_set_attribute(attribute:"solution", value:
"A fix is available, and it can be downloaded from the AIX website.

To extract the fixes from the tar file :

  zcat openssl-1.0.1.501.tar.Z | tar xvf -

IMPORTANT : If possible, it is recommended that a mksysb backup of
the system be created.  Verify it is both bootable and readable
before proceeding.

To preview the fix installation :

  installp -apYd . openssl

To install the fix package :

  installp -aXYd . openssl");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/25");
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

if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"1.0.1.500", maxpackagever:"1.0.1.500", fixpackagever:"1.0.1.501") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"1.0.1.500", maxpackagever:"1.0.1.500", fixpackagever:"1.0.1.501") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl.base", minpackagever:"1.0.1.500", maxpackagever:"1.0.1.500", fixpackagever:"1.0.1.501") > 0) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : aix_report_get()
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl.base");
}

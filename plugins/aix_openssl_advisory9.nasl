#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory openssl_advisory8.doc.
#

include("compat.inc");

if (description)
{
  script_id(74512);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/16 16:05:32 $");

  script_cve_id(
    "CVE-2014-0195",
    "CVE-2014-0198",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(67193, 67898, 67899, 67900, 67901);
  script_osvdb_id(106531, 107729, 107730, 107731, 107732);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory9.doc");
  script_summary(english:"Checks the version of the openssl packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSL installed that is
potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is potentially
affected by the following remote code execution and denial of service
vulnerabilities :

  - OpenSSL could allow an attacker to cause a buffer
    overrun situation when an attacker sends invalid DTLS
    fragments to an OpenSSL DTLS client or server, which
    forces it to run arbitrary code on a vulnerable client
    or server. (CVE-2014-0195)

  - An attacker could cause a denial of service by
    exploiting a flaw in the do_ssl3_write function via a
    NULL pointer dereference. NOTE: Only versions 1.0.1.500
    through 1.0.1.510 are vulnerable. (CVE-2014-0198)

  - An attacker could cause a denial of service by sending
    an invalid DTLS handshake to an OpenSSL DTLS client,
    resulting in recursive execution of code and an eventual
    crash. (CVE-2014-0221)

  - An attacker could use a man-in-the-middle (MITM) attack
    to force the use of weak keying material in OpenSSL
    SSL/TLS clients and servers. The attacker could decrypt
    and modify traffic from the attacked client and server.
    The attack can only be performed between a vulnerable
    client and server. (CVE-2014-0224)

  - An attacker could cause a denial of service by
    exploiting OpenSSL's anonymous ECDH cipher suites
    present within OpenSSL clients. (CVE-2014-3470)");

  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory9.asc");
  script_set_attribute(attribute:"see_also", value:"https://www14.software.ibm.com/webapp/iwm/web/preLogin.do?source=aixbp");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the AIX website.

To extract the fixes from the tar file :

  - For OpenSSL 1.0.1 version :
    zcat openssl-1.0.1.511.tar.Z | tar xvf -

  - For OpenSSL 0.9.8 version :
    zcat openssl-0.9.8.2502.tar.Z | tar xvf -

  - For OpenSSL 12.9.8 version :
    zcat openssl-12.9.8.2502.tar.Z | tar xvf

IMPORTANT : If possible, it is recommended that a mksysb backup of the
system be created. Verify it is both bootable and readable before
proceeding.

To preview the fix installation :

  installp -apYd . openssl

To install the fix package :

  installp -aXYd . openssl");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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

#0.9.8.2502
if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"0.9.8.401", maxpackagever:"0.9.8.2501", fixpackagever:"0.9.8.2502") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"0.9.8.401", maxpackagever:"0.9.8.2501", fixpackagever:"0.9.8.2502") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl.base", minpackagever:"0.9.8.401", maxpackagever:"0.9.8.2501", fixpackagever:"0.9.8.2502") > 0) flag++;

#1.0.1.511
if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"1.0.1.500", maxpackagever:"1.0.1.510", fixpackagever:"1.0.1.511") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"1.0.1.500", maxpackagever:"1.0.1.510", fixpackagever:"1.0.1.511") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl.base", minpackagever:"1.0.1.500", maxpackagever:"1.0.1.510", fixpackagever:"1.0.1.511") > 0) flag++;

#12.9.8.2502
if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"12.9.8.1100", maxpackagever:"12.9.8.2501", fixpackagever:"12.9.8.2502") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"12.9.8.1100", maxpackagever:"12.9.8.2501", fixpackagever:"12.9.8.2502") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl.base", minpackagever:"12.9.8.1100", maxpackagever:"12.9.8.2501", fixpackagever:"12.9.8.2502") > 0) flag++;

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

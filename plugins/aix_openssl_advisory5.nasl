#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory openssl_advisory5.asc.
#

include("compat.inc");

if (description)
{
  script_id(73563);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/01 17:47:58 $");

  script_cve_id("CVE-2013-0166", "CVE-2013-0169");
  script_bugtraq_id(57778, 60268);
  script_osvdb_id(89848, 89865);
  script_xref(name:"CERT", value:"737740");

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory5.asc");
  script_summary(english:"Checks the version of the openssl packages");

  script_set_attribute(attribute:"synopsis", value:"The remote AIX host is running a vulnerable version of OpenSSL.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL running on the remote host is affected by the
following vulnerabilities :

  - The TLS protocol 1.1 and 1.2 and the DTLS protocol 1.0
    and 1.2, as used in OpenSSL, OpenJDK, PolarSSL, and
    other products, do not properly consider timing side-
    channel attacks on a MAC check requirement during the
    processing of malformed CBC padding, which allows
    remote attackers to conduct distinguishing attacks and
    plaintext-recovery attacks via statistical analysis of
    timing data for crafted packets, aka the 'Lucky
    Thirteen' issue. (CVE-2013-0169)

  - OpenSSL before 0.9.8y, 1.0.0 before 1.0.0k, and 1.0.1
    before 1.0.1d does not properly perform signature
    verification for OCSP responses, which allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) via an invalid key.
    (CVE-2013-0166)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory5.asc");
  script_set_attribute(attribute:"see_also", value:"https://www14.software.ibm.com/webapp/iwm/web/preLogin.do?source=aixbp");
  script_set_attribute(attribute:"solution", value:
"A fix is available, and it can be downloaded from the AIX website.

To extract the fixes from the tar file :

  zcat openssl-0.9.8.2500.tar.Z | tar xvf -
  or
  zcat openssl-fips-12.9.8.2500.tar.Z | tar xvf -

IMPORTANT : If possible, it is recommended that a mksysb backup of
the system be created.  Verify it is both bootable and readable
before proceeding.

To preview the fix installation :

  installp -apYd . openssl

To install the fix package :

  installp -aXYd . openssl");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/15");
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

if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.2400", fixpackagever:"0.9.8.2500") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.2400", fixpackagever:"0.9.8.2500") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.2400", fixpackagever:"0.9.8.2500") > 0) flag++;
if (aix_check_package(release:"5.3", package:"openssl-fips.base", minpackagever:"0.0.0.0", maxpackagever:"12.9.8.2400", fixpackagever:"12.9.8.2500") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl-fips.base", minpackagever:"0.0.0.0", maxpackagever:"12.9.8.2400", fixpackagever:"12.9.8.2500") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl-fips.base", minpackagever:"0.0.0.0", maxpackagever:"12.9.8.2400", fixpackagever:"12.9.8.2500") > 0) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl.base / openssl-fips.base");
}

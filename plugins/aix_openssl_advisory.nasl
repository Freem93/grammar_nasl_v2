#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory openssl_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(73559);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id("CVE-2009-3245", "CVE-2010-0433", "CVE-2010-0740");
  script_bugtraq_id(38533, 38562, 39013);
  script_osvdb_id(62719, 62844, 63299);

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory.asc");
  script_summary(english:"Checks the version of the openssl packages");

  script_set_attribute(attribute:"synopsis", value:"The remote AIX host is running a vulnerable version of OpenSSL.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL running on the remote host is affected by the
following vulnerabilities :

  - In TLS connections, certain incorrectly formatted
    records can cause an OpenSSL client or server to crash
    due to a read attempt at NULL. OpenSSL before 0.9.8m
    does not check for a NULL return value from bn_wexpand
    function calls in (1) crypto/bn/bn_div.c, (2)
    crypto/bn/bn_gf2m.c, (3) crypto/ec/ec2_smpl.c, and (4)
    engines e_ubsec.c, which has an unspecified impact and
    context-dependent attack vectors. (CVE-2009-3245)

  - The kssl_keytab_is_available function in ssl/kssl.c in
    OpenSSL before 0.9.8n, when Kerberos is enabled but
    Kerberos configuration files cannot be opened, does not
    check a certain return value, which allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and daemon crash) via SSL cipher
    negotiation, as demonstrated by a chroot installation of
    Dovecot or stunnel without Kerberos configuration files
    inside the chroot. (CVE-2010-0433)

  - The ssl3_get_record function in ssl/s3_pkt.c in OpenSSL
    0.9.8f through 0.9.8m allows remote attackers to cause a
    denial of service (crash) via a malformed record in a
    TLS connection that triggers a NULL pointer dereference,
    related to the minor version number. (CVE-2010-0740)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory.asc");
  script_set_attribute(attribute:"see_also", value:"https://www14.software.ibm.com/webapp/iwm/web/preLogin.do?source=aixbp");
  script_set_attribute(attribute:"solution", value:
"A fix is available, and it can be downloaded from the AIX website.

To extract the fixes from the tar file :

  zcat openssl.0.9.8.1103.tar.Z | tar xvf -
  or
  zcat openssl-fips.12.9.8.1103.tar.Z | tar xvf -
  or
  zcat openssl.0.9.8.806.tar.Z | tar xvf -

IMPORTANT : If possible, it is recommended that a mksysb backup of
the system be created.  Verify it is both bootable and readable
before proceeding.

To preview the fix installation :

  installp -apYd . openssl

To install the fix package :

  installp -aXYd . openssl");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/21");
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
if ( oslevel != "AIX-5.2" && oslevel != "AIX-5.3" && oslevel != "AIX-6.1" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.2 / 5.3 / 6.1", oslevel);
}
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;

if (aix_check_package(release:"5.2", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.805", fixpackagever:"0.9.8.806") > 0) flag++;
if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.1102", fixpackagever:"0.9.8.1103") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.1102", fixpackagever:"0.9.8.1103") > 0) flag++;
if (aix_check_package(release:"5.3", package:"openssl-fips.base", minpackagever:"0.0.0.0", maxpackagever:"12.9.8.1102", fixpackagever:"12.9.8.1103") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl-fips.base", minpackagever:"0.0.0.0", maxpackagever:"12.9.8.1102", fixpackagever:"12.9.8.1103") > 0) flag++;

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

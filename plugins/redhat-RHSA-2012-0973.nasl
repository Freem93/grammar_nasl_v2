#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0973. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59599);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/05 16:04:22 $");

  script_xref(name:"RHSA", value:"2012:0973");

  script_name(english:"RHEL 6 : nss, nss-util, and nspr (RHSA-2012:0973)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss, nss-util, and nspr packages that fix one security issue,
several bugs, and add various enhancements are now available for Red
Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

It was found that a Certificate Authority (CA) issued a subordinate CA
certificate to its customer, that could be used to issue certificates
for any name. This update renders the subordinate CA certificate as
untrusted. (BZ#798533)

Note: This fix only applies to applications using the NSS Builtin
Object Token. It does not render the certificates untrusted for
applications that use the NSS library, but do not use the NSS Builtin
Object Token.

The nspr package has been upgraded to upstream version 4.9, which
provides a number of bug fixes and enhancements over the previous
version. (BZ#799193)

The nss-util package has been upgraded to upstream version 3.13.3,
which provides a number of bug fixes and enhancements over the
previous version. (BZ#799192)

The nss package has been upgraded to upstream version 3.13.3, which
provides numerous bug fixes and enhancements over the previous
version. In particular, SSL 2.0 is now disabled by default, support
for SHA-224 has been added, PORT_ErrorToString and PORT_ErrorToName
now return the error message and symbolic name of an NSS error code,
and NSS_GetVersion now returns the NSS version string. (BZ#744070)

These updated nss, nss-util, and nspr packages also provide fixes for
the following bugs :

* A PEM module internal function did not clean up memory when
detecting a non-existent file name. Consequently, memory leaks in
client code occurred. The code has been improved to deallocate such
temporary objects and as a result the reported memory leakage is gone.
(BZ#746632)

* Recent changes to NSS re-introduced a problem where applications
could not use multiple SSL client certificates in the same process.
Therefore, any attempt to run commands that worked with multiple SSL
client certificates, such as the 'yum repolist' command, resulted in a
re-negotiation handshake failure. With this update, a revised patch
correcting this problem has been applied to NSS, and using multiple
SSL client certificates in the same process is now possible again.
(BZ#761086)

* The PEM module did not fully initialize newly constructed objects
with function pointers set to NULL. Consequently, a segmentation
violation in libcurl was sometimes experienced while accessing a
package repository. With this update, the code has been changed to
fully initialize newly allocated objects. As a result, updates can now
be installed without problems. (BZ#768669)

* A lack-of-robustness flaw caused the administration server for Red
Hat Directory Server to terminate unexpectedly because the mod_nss
module made nss calls before initializing nss as per the documented
API. With this update, nss protects itself against being called before
it has been properly initialized by the caller. (BZ#784674)

* Compilation errors occurred with some compilers when compiling code
against NSS 3.13.1. The following error message was displayed :

pkcs11n.h:365:26: warning: '__GNUC_MINOR' is not defined

An upstream patch has been applied to improve the code and the problem
no longer occurs. (BZ#795693)

* Unexpected terminations were reported in the messaging daemon
(qpidd) included in Red Hat Enterprise MRG after a recent update to
nss. This occurred because qpidd made nss calls before initializing
nss. These updated packages prevent qpidd and other affected processes
that call nss without initializing as mandated by the API from
crashing. (BZ#797426)

Users of NSS, NSPR, and nss-util are advised to upgrade to these
updated packages, which fix these issues and add these enhancements.
After installing this update, applications using NSS, NSPR, or
nss-util must be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0973.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0973";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", reference:"nspr-4.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"nspr-debuginfo-4.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"nspr-devel-4.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"nss-3.13.3-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"nss-debuginfo-3.13.3-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"nss-devel-3.13.3-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"nss-pkcs11-devel-3.13.3-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nss-sysinit-3.13.3-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nss-sysinit-3.13.3-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nss-sysinit-3.13.3-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nss-tools-3.13.3-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nss-tools-3.13.3-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nss-tools-3.13.3-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"nss-util-3.13.3-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"nss-util-debuginfo-3.13.3-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"nss-util-devel-3.13.3-2.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-debuginfo / nspr-devel / nss / nss-debuginfo / etc");
  }
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0213. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64387);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_xref(name:"RHSA", value:"2013:0213");

  script_name(english:"RHEL 6 : nss, nss-util, and nspr (RHSA-2013:0213)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss, nss-util, and nspr packages that fix one security issue,
various bugs, and add enhancements are now available for Red Hat
Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

It was found that a Certificate Authority (CA) mis-issued two
intermediate certificates to customers. These certificates could be
used to launch man-in-the-middle attacks. This update renders those
certificates as untrusted. This covers all uses of the certificates,
including SSL, S/MIME, and code signing. (BZ#890605)

Note: This fix only applies to applications using the NSS Builtin
Object Token. It does not render the certificates untrusted for
applications that use the NSS library, but do not use the NSS Builtin
Object Token.

In addition, the nss package has been upgraded to upstream version
3.13.6, the nss-util package has been upgraded to upstream version
3.13.6, and the nspr package has been upgraded to upstream version
4.9.2. These updates provide a number of bug fixes and enhancements
over the previous versions. (BZ#891663, BZ#891670, BZ#891661)

Users of NSS, NSPR, and nss-util are advised to upgrade to these
updated packages, which fix these issues and add these enhancements.
After installing this update, applications using NSS, NSPR, or
nss-util must be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-20.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0213.html"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:0213";
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
  if (rpm_check(release:"RHEL6", reference:"nspr-4.9.2-0.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nspr-debuginfo-4.9.2-0.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nspr-devel-4.9.2-0.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-3.13.6-2.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-debuginfo-3.13.6-2.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-devel-3.13.6-2.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-pkcs11-devel-3.13.6-2.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nss-sysinit-3.13.6-2.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nss-sysinit-3.13.6-2.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nss-sysinit-3.13.6-2.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nss-tools-3.13.6-2.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nss-tools-3.13.6-2.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nss-tools-3.13.6-2.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-util-3.13.6-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-util-debuginfo-3.13.6-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-util-devel-3.13.6-1.el6_3")) flag++;


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

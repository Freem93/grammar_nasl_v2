#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1307. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77896);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/06 15:50:59 $");

  script_cve_id("CVE-2014-1568");
  script_osvdb_id(112036);
  script_xref(name:"RHSA", value:"2014:1307");

  script_name(english:"RHEL 5 / 6 / 7 : nss (RHSA-2014:1307)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss packages that fix one security issue are now available for
Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

A flaw was found in the way NSS parsed ASN.1 (Abstract Syntax Notation
One) input from certain RSA signatures. A remote attacker could use
this flaw to forge RSA certificates by providing a specially crafted
signature to an application using NSS. (CVE-2014-1568)

Red Hat would like to thank the Mozilla project for reporting this
issue. Upstream acknowledges Antoine Delignat-Lavaud and Intel Product
Security Incident Response Team as the original reporters.

All NSS users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing
this update, applications using NSS must be restarted for this update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-1568.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1307.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1307";
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
  if (rpm_check(release:"RHEL5", reference:"nss-3.16.1-4.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", reference:"nss-debuginfo-3.16.1-4.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", reference:"nss-devel-3.16.1-4.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", reference:"nss-pkcs11-devel-3.16.1-4.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"nss-tools-3.16.1-4.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"nss-tools-3.16.1-4.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"nss-tools-3.16.1-4.el5_11")) flag++;


  if (rpm_check(release:"RHEL6", reference:"nss-3.16.1-7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-debuginfo-3.16.1-7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-devel-3.16.1-7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-pkcs11-devel-3.16.1-7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-softokn-3.14.3-12.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-softokn-debuginfo-3.14.3-12.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-softokn-devel-3.14.3-12.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-softokn-freebl-3.14.3-12.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-softokn-freebl-devel-3.14.3-12.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nss-sysinit-3.16.1-7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nss-sysinit-3.16.1-7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nss-sysinit-3.16.1-7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nss-tools-3.16.1-7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nss-tools-3.16.1-7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nss-tools-3.16.1-7.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-util-3.16.1-2.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-util-debuginfo-3.16.1-2.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-util-devel-3.16.1-2.el6_5")) flag++;


  if (rpm_check(release:"RHEL7", reference:"nss-3.16.2-7.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-debuginfo-3.16.2-7.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-devel-3.16.2-7.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-pkcs11-devel-3.16.2-7.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-3.16.2-2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-debuginfo-3.16.2-2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-devel-3.16.2-2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-freebl-3.16.2-2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-freebl-devel-3.16.2-2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"nss-sysinit-3.16.2-7.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nss-sysinit-3.16.2-7.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"nss-tools-3.16.2-7.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nss-tools-3.16.2-7.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-util-3.16.2-2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-util-debuginfo-3.16.2-2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-util-devel-3.16.2-2.el7_0")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-debuginfo / nss-devel / nss-pkcs11-devel / nss-softokn / etc");
  }
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0792. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50340);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/01/04 15:51:48 $");

  script_cve_id("CVE-2010-3904");
  script_bugtraq_id(44219);
  script_osvdb_id(69117);
  script_xref(name:"RHSA", value:"2010:0792");

  script_name(english:"RHEL 5 : kernel (RHSA-2010:0792)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issue :

* The rds_page_copy_user() function in the Linux kernel Reliable
Datagram Sockets (RDS) protocol implementation was missing sanity
checks. A local, unprivileged user could use this flaw to escalate
their privileges. (CVE-2010-3904, Important)

Red Hat would like to thank Dan Rosenberg of Virtual Security Research
for reporting this issue.

Users should upgrade to these updated packages, which contain a
backported patch to correct this issue. The system must be rebooted
for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3904.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0792.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0792";
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
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-PAE-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debug-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debug-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debug-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debug-devel-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-devel-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-devel-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-devel-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"kernel-doc-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"kernel-headers-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-headers-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-headers-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-kdump-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-xen-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-xen-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-xen-devel-2.6.18-194.17.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-194.17.4.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-devel / kernel-debug / etc");
  }
}

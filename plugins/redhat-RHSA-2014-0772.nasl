#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0772. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79031);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/06 15:40:58 $");

  script_cve_id("CVE-2012-6638", "CVE-2014-1737", "CVE-2014-1738");
  script_xref(name:"RHSA", value:"2014:0772");

  script_name(english:"RHEL 5 : kernel (RHSA-2014:0772)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix three security issues and two bugs
are now available for Red Hat Enterprise Linux 5.9 Extended Update
Support.

The Red Hat Security Response Team has rated this update as having
Important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A flaw was found in the way the Linux kernel's floppy driver handled
user space provided data in certain error code paths while processing
FDRAWCMD IOCTL commands. A local user with write access to /dev/fdX
could use this flaw to free (using the kfree() function) arbitrary
kernel memory. (CVE-2014-1737, Important)

* It was found that the Linux kernel's floppy driver leaked internal
kernel memory addresses to user space during the processing of the
FDRAWCMD IOCTL command. A local user with write access to /dev/fdX
could use this flaw to obtain information about the kernel heap
arrangement. (CVE-2014-1738, Low)

Note: A local user with write access to /dev/fdX could use these two
flaws (CVE-2014-1737 in combination with CVE-2014-1738) to escalate
their privileges on the system.

* A flaw was found in the way the Linux kernel's TCP/IP protocol suite
implementation handled TCP packets with both the SYN and FIN flags
set. A remote attacker could use this flaw to consume an excessive
amount of resources on the target system, potentially resulting in a
denial of service. (CVE-2012-6638, Moderate)

Red Hat would like to thank Matthew Daley for reporting CVE-2014-1737
and CVE-2014-1738.

This update also fixes the following bugs :

* While under heavy load, some Fibre Channel storage devices, such as
Hitachi and HP Open-V series, can send a logout (LOGO) message to the
host system. However, due to a bug in the lpfc driver, this could
result in a loss of active paths to the storage and the paths could
not be recovered without manual intervention. This update corrects the
lpfc driver to ensure automatic recovery of the lost paths to the
storage in this scenario. (BZ#1096060)

* A bug in the futex system call could result in an overflow when
passing a very large positive timeout. As a consequence, the
FUTEX_WAIT operation did not work as intended and the system call was
timing out immediately. A backported patch fixes this bug by limiting
very large positive timeouts to the maximal supported value.
(BZ#1091831)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-6638.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-1737.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-1738.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0772.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
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
if (! ereg(pattern:"^5\.9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.9", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0772";
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
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-PAE-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-PAE-debuginfo-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debug-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-debug-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debug-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debug-devel-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debuginfo-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-debuginfo-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debuginfo-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debuginfo-common-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-debuginfo-common-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debuginfo-common-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-devel-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-devel-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-devel-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", reference:"kernel-doc-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"kernel-headers-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-headers-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-headers-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-kdump-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-xen-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-xen-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-xen-debuginfo-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-xen-debuginfo-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-xen-devel-2.6.18-348.27.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-348.27.1.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-debuginfo / kernel-PAE-devel / etc");
  }
}

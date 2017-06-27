#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1450. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78974);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-2224", "CVE-2013-2852", "CVE-2013-4299");
  script_bugtraq_id(63183);
  script_osvdb_id(94034);
  script_xref(name:"RHSA", value:"2013:1450");

  script_name(english:"RHEL 6 : kernel (RHSA-2013:1450)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix three security issues and several
bugs are now available for Red Hat Enterprise Linux 6.3 Extended
Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* It was found that the fix for CVE-2012-3552 released via
RHSA-2012:1540 introduced an invalid free flaw in the Linux kernel's
TCP/IP protocol suite implementation. A local, unprivileged user could
use this flaw to corrupt kernel memory via crafted sendmsg() calls,
allowing them to cause a denial of service or, potentially, escalate
their privileges on the system. (CVE-2013-2224, Important)

* An information leak flaw was found in the way Linux kernel's device
mapper subsystem, under certain conditions, interpreted data written
to snapshot block devices. An attacker could use this flaw to read
data from disk blocks in free space, which are normally inaccessible.
(CVE-2013-4299, Moderate)

* A format string flaw was found in the b43_do_request_fw() function
in the Linux kernel's b43 driver implementation. A local user who is
able to specify the 'fwpostfix' b43 module parameter could use this
flaw to cause a denial of service or, potentially, escalate their
privileges. (CVE-2013-2852, Low)

Red Hat would like to thank Fujitsu for reporting CVE-2013-4299, and
Kees Cook for reporting CVE-2013-2852.

This update also fixes the following bugs :

* An insufficiently designed calculation in the CPU accelerator could
cause an arithmetic overflow in the set_cyc2ns_scale() function if the
system uptime exceeded 208 days prior to using kexec to boot into a
new kernel. This overflow led to a kernel panic on the systems using
the Time Stamp Counter (TSC) clock source, primarily the systems using
Intel Xeon E5 processors that do not reset TSC on soft power cycles. A
patch has been applied to modify the calculation so that this
arithmetic overflow and kernel panic can no longer occur under these
circumstances. (BZ#1004185)

* A race condition in the abort task and SPP device task management
path of the isci driver could, under certain circumstances, cause the
driver to fail cleaning up timed-out I/O requests that were pending on
an SAS disk device. As a consequence, the kernel removed such a device
from the system. A patch applied to the isci driver fixes this problem
by sending the task management function request to the SAS drive
anytime the abort function is entered and the task has not completed.
The driver now cleans up timed-out I/O requests as expected in this
situation. (BZ#1007467)

* A kernel panic could occur during path failover on systems using
multiple iSCSI, FC or SRP paths to connect an iSCSI initiator and an
iSCSI target. This happened because a race condition in the SCSI
driver allowed removing a SCSI device from the system before
processing its run queue, which led to a NULL pointer dereference. The
SCSI driver has been modified and the race is now avoided by holding a
reference to a SCSI device run queue while it is active. (BZ#1008507)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2224.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2852.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4299.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1450.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/22");
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
if (! ereg(pattern:"^6\.3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.3", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1450";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debug-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debug-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debug-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debug-devel-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debuginfo-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-devel-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-devel-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-devel-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", reference:"kernel-doc-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", reference:"kernel-firmware-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-headers-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-headers-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-headers-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-kdump-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"perf-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"perf-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"perf-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"perf-debuginfo-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"perf-debuginfo-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"python-perf-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"python-perf-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"python-perf-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-279.37.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-279.37.2.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debug / kernel-debug-debuginfo / kernel-debug-devel / etc");
  }
}

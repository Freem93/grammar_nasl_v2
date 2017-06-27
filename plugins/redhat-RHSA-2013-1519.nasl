#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1519. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78978);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2012-4508", "CVE-2013-4299");
  script_osvdb_id(88156, 98634);
  script_xref(name:"RHSA", value:"2013:1519");

  script_name(english:"RHEL 6 : kernel (RHSA-2013:1519)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two security issues and several bugs
are now available for Red Hat Enterprise Linux 6.2 Extended Update
Support.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A race condition was found in the way asynchronous I/O and
fallocate() interacted when using the ext4 file system. A local,
unprivileged user could use this flaw to expose random data from an
extent whose data blocks have not yet been written, and thus contain
data from a deleted file. (CVE-2012-4508, Important)

* An information leak flaw was found in the way Linux kernel's device
mapper subsystem, under certain conditions, interpreted data written
to snapshot block devices. An attacker could use this flaw to read
data from disk blocks in free space, which are normally inaccessible.
(CVE-2013-4299, Moderate)

Red Hat would like to thank Theodore Ts'o for reporting CVE-2012-4508,
and Fujitsu for reporting CVE-2013-4299. Upstream acknowledges Dmitry
Monakhov as the original reporter of CVE-2012-4508.

This update also fixes the following bugs :

* When the Audit subsystem was under heavy load, it could loop
infinitely in the audit_log_start() function instead of failing over
to the error recovery code. This would cause soft lockups in the
kernel. With this update, the timeout condition in the
audit_log_start() function has been modified to properly fail over
when necessary. (BZ#1017898)

* When handling Memory Type Range Registers (MTRRs), the
stop_one_cpu_nowait() function could potentially be executed in
parallel with the stop_machine() function, which resulted in a
deadlock. The MTRR handling logic now uses the stop_machine() function
and makes use of mutual exclusion to avoid the aforementioned
deadlock. (BZ#1017902)

* Power-limit notification interrupts were enabled by default. This
could lead to degradation of system performance or even render the
system unusable on certain platforms, such as Dell PowerEdge servers.
Power-limit notification interrupts have been disabled by default and
a new kernel command line parameter 'int_pln_enable' has been added to
allow users to observe these events using the existing system
counters. Power-limit notification messages are also no longer
displayed on the console. The affected platforms no longer suffer from
degraded system performance due to this problem. (BZ#1020519)

* Package level thermal and power limit events are not defined as MCE
errors for the x86 architecture. However, the mcelog utility
erroneously reported these events as MCE errors with the following
message :

kernel: [Hardware Error]: Machine check events logged

Package level thermal and power limit events are no longer reported as
MCE errors by mcelog. When these events are triggered, they are now
reported only in the respective counters in sysfs (specifically,
/sys/devices/system/cpu/cpu<number>/thermal_throttle/). (BZ#1021950)

* An insufficiently designed calculation in the CPU accelerator could
cause an arithmetic overflow in the set_cyc2ns_scale() function if the
system uptime exceeded 208 days prior to using kexec to boot into a
new kernel. This overflow led to a kernel panic on systems using the
Time Stamp Counter (TSC) clock source, primarily systems using Intel
Xeon E5 processors that do not reset TSC on soft power cycles. A patch
has been applied to modify the calculation so that this arithmetic
overflow and kernel panic can no longer occur under these
circumstances. (BZ#1024453)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4508.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4299.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1519.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/13");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1519";
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
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-debug-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-debug-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-debug-devel-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-debuginfo-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-devel-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-devel-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-devel-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-doc-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-firmware-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-headers-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-headers-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-headers-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-kdump-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"perf-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"perf-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"perf-debuginfo-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"perf-debuginfo-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"python-perf-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"python-perf-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"python-perf-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-220.45.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-220.45.1.el6")) flag++;


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

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1401. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64059);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/05 16:17:29 $");

  script_cve_id("CVE-2012-3412");
  script_xref(name:"RHSA", value:"2012:1401");

  script_name(english:"RHEL 6 : kernel (RHSA-2012:1401)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 6.2 Extended Update
Support.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issue :

* A flaw was found in the way socket buffers (skb) requiring TSO (TCP
segment offloading) were handled by the sfc driver. If the skb did not
fit within the minimum-size of the transmission queue, the network
card could repeatedly reset itself. A remote attacker could use this
flaw to cause a denial of service. (CVE-2012-3412, Important)

Red Hat would like to thank Ben Hutchings of Solarflare (tm) for
reporting CVE-2012-3412.

This update also fixes the following bugs :

* Previously, when a server attempted to shut down a socket, the
svc_tcp_sendto() function set the XPT_CLOSE variable if the entire
reply failed to be transmitted. However, before XPT_CLOSE could be
acted upon, other threads could send further replies before the socket
was really shut down. Consequently, data corruption could occur in the
RPC record marker. With this update, send operations on a closed
socket are stopped immediately, thus preventing this bug. (BZ#853256)

* When a PIT (Programmable Interval Timer) MSB (Most Significant Byte)
transition occurred very close to an SMI (System Management Interrupt)
execution, the pit_verify_msb() function did not see the MSB
transition. Consequently, the pit_expect_msb() function returned
success incorrectly, eventually causing a large clock drift in the
quick_pit_calibrate() function. As a result, the TSC (Time Stamp
Counter) calibration on some systems was off by +- 20 MHz, which led
to inaccurate timekeeping or ntp synchronization failures. This update
fixes pit_expect_msb() and the clock drift no longer occurs in the
described scenario. (BZ#853952)

* Sometimes, the crypto allocation code could become unresponsive for
60 seconds or multiples thereof due to an incorrect notification
mechanism. This could cause applications, like Openswan, to become
unresponsive. The notification mechanism has been improved to avoid
such hangs. (BZ#854475)

* Traffic to the NFS server could trigger a kernel oops in the
svc_tcp_clear_pages() function. The source code has been modified, and
the kernel oops no longer occurs in this scenario. (BZ#856105)

* Under certain circumstances, a system crash could result in data
loss on XFS file systems. If files were created immediately before the
file system was left to idle for a long period of time and then the
system crashed, those files could appear as zero-length once the file
system was remounted. This occurred even if a sync or fsync was run on
the files. This was because XFS was not correctly idling the journal,
and therefore it incorrectly replayed the inode allocation
transactions upon mounting after the system crash, which zeroed the
file size. This problem has been fixed by re-instating the periodic
journal idling logic to ensure that all metadata is flushed within 30
seconds of modification, and the journal is updated to prevent
incorrect recovery operations from occurring. (BZ#856685)

* On architectures with the 64-bit cputime_t type, it was possible to
trigger the 'divide by zero' error, namely, on long-lived processes. A
patch has been applied to address this problem, and the 'divide by
zero' error no longer occurs under these circumstances. (BZ#856702)

Users should upgrade to these updated packages, which contain
backported patches to resolve these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3412.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1401.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
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
  rhsa = "RHSA-2012:1401";
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
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-debug-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-debug-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-debug-devel-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-debuginfo-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-devel-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-devel-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-devel-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-doc-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-firmware-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-headers-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-headers-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-headers-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-kdump-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"perf-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"perf-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"perf-debuginfo-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"perf-debuginfo-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"python-perf-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"python-perf-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"python-perf-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-220.28.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-220.28.1.el6")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debug / kernel-debug-debuginfo / kernel-debug-devel / etc");
  }
}

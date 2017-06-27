#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0494 and 
# CentOS Errata and Security Advisory 2016:0494 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(90123);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2016-0774");
  script_osvdb_id(122968);
  script_xref(name:"RHSA", value:"2016:0494");

  script_name(english:"CentOS 6 : kernel (CESA-2016:0494)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue, several bugs, and
add one enhancement are now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* It was found that the fix for CVE-2015-1805 incorrectly kept buffer
offset and buffer length in sync on a failed atomic read, potentially
resulting in a pipe buffer state corruption. A local, unprivileged
user could use this flaw to crash the system or leak kernel memory to
user space. (CVE-2016-0774, Moderate)

The security impact of this issue was discovered by Red Hat.

This update also fixes the following bugs :

* In the anon_vma structure, the degree counts number of child
anon_vmas and of VMAs which points to this anon_vma. Failure to
decrement the parent's degree in the unlink_anon_vma() function, when
its list was empty, previously triggered a BUG_ON() assertion. The
provided patch makes sure the anon_vma degree is always decremented
when the VMA list is empty, thus fixing this bug. (BZ#1318364)

* When running Internet Protocol Security (IPSEC) on external storage
encrypted with LUKS under a substantial load on the system, data
corruptions could previously occur. A set of upstream patches has been
provided, and data corruption is no longer reported in this situation.
(BZ#1298994)

* Due to prematurely decremented calc_load_task, the calculated load
average was off by up to the number of CPUs in the machine. As a
consequence, job scheduling worked improperly causing a drop in the
system performance. This update keeps the delta of the CPU going into
NO_HZ idle separately, and folds the pending idle delta into the
global active count while correctly aging the averages for the
idle-duration when leaving NO_HZ mode. Now, job scheduling works
correctly, ensuring balanced CPU load. (BZ#1300349)

* Due to a regression in the Red Hat Enterprise Linux 6.7 kernel, the
cgroup OOM notifier accessed a cgroup-specific internal data structure
without a proper locking protection, which led to a kernel panic. This
update adjusts the cgroup OOM notifier to lock internal data properly,
thus fixing the bug. (BZ#1302763)

* GFS2 had a rare timing window that sometimes caused it to reference
an uninitialized variable. Consequently, a kernel panic occurred. The
code has been changed to reference the correct value during this
timing window, and the kernel no longer panics. (BZ#1304332)

* Due to a race condition whereby a cache operation could be submitted
after a cache object was killed, the kernel occasionally crashed on
systems running the cachefilesd service. The provided patch prevents
the race condition by adding serialization in the code that makes the
object unavailable. As a result, all subsequent operations targetted
on the object are rejected and the kernel no longer crashes in this
scenario. (BZ#1308471)

This update also adds this enhancement :

* The lpfc driver has been updated to version 11.0.0.4. (BZ#1297838)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add this
enhancement. The system must be rebooted for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-March/021769.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d35d42d6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-abi-whitelists-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-573.22.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

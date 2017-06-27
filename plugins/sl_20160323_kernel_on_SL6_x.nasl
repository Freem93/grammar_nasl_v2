#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(90144);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2015-1805", "CVE-2016-0774");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - It was found that the fix for CVE-2015-1805 incorrectly
    kept buffer offset and buffer length in sync on a failed
    atomic read, potentially resulting in a pipe buffer
    state corruption. A local, unprivileged user could use
    this flaw to crash the system or leak kernel memory to
    user space. (CVE-2016-0774, Moderate)

This update also fixes the following bugs :

  - In the anon_vma structure, the degree counts number of
    child anon_vmas and of VMAs which points to this
    anon_vma. Failure to decrement the parent's degree in
    the unlink_anon_vma() function, when its list was empty,
    previously triggered a BUG_ON() assertion. The provided
    patch makes sure the anon_vma degree is always
    decremented when the VMA list is empty, thus fixing this
    bug.

  - When running Internet Protocol Security (IPSEC) on
    external storage encrypted with LUKS under a substantial
    load on the system, data corruptions could previously
    occur. A set of upstream patches has been provided, and
    data corruption is no longer reported in this situation.

  - Due to prematurely decremented calc_load_task, the
    calculated load average was off by up to the number of
    CPUs in the machine. As a consequence, job scheduling
    worked improperly causing a drop in the system
    performance. This update keeps the delta of the CPU
    going into NO_HZ idle separately, and folds the pending
    idle delta into the global active count while correctly
    aging the averages for the idle-duration when leaving
    NO_HZ mode. Now, job scheduling works correctly,
    ensuring balanced CPU load.

  - Due to a regression in the Scientific Linux 6.7 kernel,
    the cgroup OOM notifier accessed a cgroup-specific
    internal data structure without a proper locking
    protection, which led to a kernel panic. This update
    adjusts the cgroup OOM notifier to lock internal data
    properly, thus fixing the bug.

  - GFS2 had a rare timing window that sometimes caused it
    to reference an uninitialized variable. Consequently, a
    kernel panic occurred. The code has been changed to
    reference the correct value during this timing window,
    and the kernel no longer panics.

  - Due to a race condition whereby a cache operation could
    be submitted after a cache object was killed, the kernel
    occasionally crashed on systems running the cachefilesd
    service. The provided patch prevents the race condition
    by adding serialization in the code that makes the
    object unavailable. As a result, all subsequent
    operations targetted on the object are rejected and the
    kernel no longer crashes in this scenario.

This update also adds this enhancement :

  - The lpfc driver has been updated to version 11.0.0.4.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1603&L=scientific-linux-errata&F=&S=&P=12268
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5cd6910"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-common-i686-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-573.22.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-573.22.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

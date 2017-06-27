#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67241);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/07/11 10:52:55 $");

  script_cve_id("CVE-2012-6544", "CVE-2012-6545", "CVE-2013-0914", "CVE-2013-1929", "CVE-2013-3222", "CVE-2013-3224", "CVE-2013-3231", "CVE-2013-3235");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64");
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
"This update fixes the following security issues :

  - Information leaks in the Linux kernel could allow a
    local, unprivileged user to leak kernel memory to
    user-space. (CVE-2012-6544, CVE-2012-6545,
    CVE-2013-3222, CVE-2013-3224, CVE-2013-3231,
    CVE-2013-3235, Low)

  - An information leak was found in the Linux kernel's
    POSIX signals implementation. A local, unprivileged user
    could use this flaw to bypass the Address Space Layout
    Randomization (ASLR) security feature. (CVE-2013-0914,
    Low)

  - A heap-based buffer overflow in the way the tg3 Ethernet
    driver parsed the vital product data (VPD) of devices
    could allow an attacker with physical access to a system
    to cause a denial of service or, potentially, escalate
    their privileges. (CVE-2013-1929, Low)

This update also fixes the following bugs :

  - Previously on system boot, devices with associated
    Reserved Memory Region Reporting (RMRR) information had
    lost their RMRR information after they were removed from
    the static identity (SI) domain. Consequently, a system
    unexpectedly terminated in an endless loop due to
    unexpected NMIs triggered by DMA errors. This problem
    was observed on HP ProLiant Generation 7 (G7) and 8
    (Gen8) systems. This update prevents non-USB devices
    that have RMRR information associated with them from
    being placed into the SI domain during system boot. HP
    ProLiant G7 and Gen8 systems that contain devices with
    the RMRR information now boot as expected.

  - Previously, the kernel's futex wait code used timeouts
    that had granularity in milliseconds. Also, when passing
    these timeouts to system calls, the kernel converted the
    timeouts to 'jiffies'. Consequently, programs could time
    out inaccurately which could lead to significant latency
    problems in certain environments. This update modifies
    the futex wait code to use a high-resolution timer
    (hrtimer) so the timeout granularity is now in
    microseconds. Timeouts are no longer converted to
    'jiffies' when passed to system calls. Timeouts passed
    to programs are now accurate and the programs time out
    as expected.

  - A recent change modified the size of the task_struct
    structure in the floating point unit (fpu) counter.
    However, on Intel Itanium systems, this change caused
    the kernel Application Binary Interface (kABI) to stop
    working properly when a previously compiled module was
    loaded, resulting in a kernel panic. With this update
    the change causing this bug has been reverted so the bug
    can no longer occur.

  - The cxgb4 driver previously did not clear data
    structures used for firmware requests. Consequently,
    when initializing some Chelsio's Terminator 4 (T4)
    adapters, a probe request could fail because the request
    was incompatible with the adapter's firmware. This
    update modifies the cxgb4 driver to properly initialize
    firmware request structures before sending a request to
    the firmware and the problem no longer occurs.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1307&L=scientific-linux-errata&T=0&P=707
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ddab17ec"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-348.12.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-348.12.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-348.12.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-348.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-348.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-348.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-348.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-348.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-348.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-348.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-348.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-348.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-348.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-348.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-348.12.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

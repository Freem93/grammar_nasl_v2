#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61221);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/11/19 11:21:01 $");

  script_cve_id("CVE-2012-0056");

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
"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issue :

  - It was found that permissions were not checked properly
    in the Linux kernel when handling the /proc/[pid]/mem
    writing functionality. A local, unprivileged user could
    use this flaw to escalate their privileges.
    (CVE-2012-0056, Important)

This update fixes the following bugs :

  - The 2.6.32-220.2.1.el6 kernel update introduced a bug in
    the Linux kernel scheduler, causing a 'WARNING: at
    kernel/sched.c:5915 thread_return' message and a call
    trace to be logged. This message was harmless, and was
    not due to any system malfunctions or adverse behavior.
    With this update, the WARN_ON_ONCE() call in the
    scheduler that caused this harmless message has been
    removed.

  - The 2.6.32-220.el6 kernel update introduced a regression
    in the way the Linux kernel maps ELF headers for kernel
    modules into kernel memory. If a third-party kernel
    module is compiled on a Scientific Linux system with a
    kernel prior to 2.6.32-220.el6, then loading that module
    on a system with 2.6.32-220.el6 kernel would result in
    corruption of one byte in the memory reserved for the
    module. In some cases, this could prevent the module
    from functioning correctly.

  - On some SMP systems the tsc may erroneously be marked as
    unstable during early system boot or while the system is
    under heavy load. A 'Clocksource tsc unstable' message
    was logged when this occurred. As a result the system
    would switch to the slower access, but higher precision
    HPET clock.

The 'tsc=reliable' kernel parameter is supposed to avoid this problem
by indicating that the system has a known good clock, however, the
parameter only affected run time checks. A fix has been put in to
avoid the boot time checks so that the TSC remains as the clock for
the duration of system runtime.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1201&L=scientific-linux-errata&T=0&P=1828
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3fac6cb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-220.4.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-220.4.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-220.4.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-220.4.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-220.4.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-220.4.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-220.4.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-220.4.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-220.4.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-220.4.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-220.4.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-220.4.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-220.4.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-220.4.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

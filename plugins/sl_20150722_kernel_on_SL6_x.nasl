#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85198);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/04 14:00:09 $");

  script_cve_id("CVE-2014-3184", "CVE-2014-3940", "CVE-2014-4652", "CVE-2014-8133", "CVE-2014-8709", "CVE-2014-9683", "CVE-2015-0239", "CVE-2015-3339");

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
"* A flaw was found in the way Linux kernel's Transparent Huge Pages
(THP) implementation handled non-huge page migration. A local,
unprivileged user could use this flaw to crash the kernel by migrating
transparent hugepages. (CVE-2014-3940, Moderate)

* A buffer overflow flaw was found in the way the Linux kernel's
eCryptfs implementation decoded encrypted file names. A local,
unprivileged user could use this flaw to crash the system or,
potentially, escalate their privileges on the system. (CVE-2014-9683,
Moderate)

* A race condition flaw was found between the chown and execve system
calls. When changing the owner of a setuid user binary to root, the
race condition could momentarily make the binary setuid root. A local,
unprivileged user could potentially use this flaw to escalate their
privileges on the system. (CVE-2015-3339, Moderate)

* Multiple out-of-bounds write flaws were found in the way the Cherry
Cymotion keyboard driver, KYE/Genius device drivers, Logitech device
drivers, Monterey Genius KB29E keyboard driver, Petalynx Maxter remote
control driver, and Sunplus wireless desktop driver handled HID
reports with an invalid report descriptor size. An attacker with
physical access to the system could use either of these flaws to write
data past an allocated memory buffer. (CVE-2014-3184, Low)

* An information leak flaw was found in the way the Linux kernel's
Advanced Linux Sound Architecture (ALSA) implementation handled access
of the user control's state. A local, privileged user could use this
flaw to leak kernel memory to user space. (CVE-2014-4652, Low)

* It was found that the espfix functionality could be bypassed by
installing a 16-bit RW data segment into GDT instead of LDT (which
espfix checks), and using that segment on the stack. A local,
unprivileged user could potentially use this flaw to leak kernel stack
addresses. (CVE-2014-8133, Low)

* An information leak flaw was found in the Linux kernel's IEEE 802.11
wireless networking implementation. When software encryption was used,
a remote attacker could use this flaw to leak up to 8 bytes of
plaintext. (CVE-2014-8709, Low)

* It was found that the Linux kernel KVM subsystem's sysenter
instruction emulation was not sufficient. An unprivileged guest user
could use this flaw to escalate their privileges by tricking the
hypervisor to emulate a SYSENTER instruction in 16-bit mode, if the
guest OS did not initialize the SYSENTER model-specific registers
(MSRs). Note: Certified guest operating systems for Scientific Linux
with KVM do initialize the SYSENTER MSRs and are thus not vulnerable
to this issue when running on a KVM hypervisor. (CVE-2015-0239, Low)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=7966
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5dcf96b0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-573.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

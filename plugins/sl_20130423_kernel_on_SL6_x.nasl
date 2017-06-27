#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66214);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/04/25 10:47:01 $");

  script_cve_id("CVE-2012-6537", "CVE-2012-6546", "CVE-2012-6547", "CVE-2013-0349", "CVE-2013-0913", "CVE-2013-1767", "CVE-2013-1773", "CVE-2013-1774", "CVE-2013-1792", "CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798", "CVE-2013-1826", "CVE-2013-1827");

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
"* An integer overflow flaw, leading to a heap-based buffer overflow,
was found in the way the Intel i915 driver in the Linux kernel handled
the allocation of the buffer used for relocation copies. A local user
with console access could use this flaw to cause a denial of service
or escalate their privileges. (CVE-2013-0913, Important)

* A buffer overflow flaw was found in the way UTF-8 characters were
converted to UTF-16 in the utf8s_to_utf16s() function of the Linux
kernel's FAT file system implementation. A local user able to mount a
FAT file system with the 'utf8=1' option could use this flaw to crash
the system or, potentially, to escalate their privileges.
(CVE-2013-1773, Important)

* A flaw was found in the way KVM handled guest time updates when the
buffer the guest registered by writing to the MSR_KVM_SYSTEM_TIME
machine state register (MSR) crossed a page boundary. A privileged
guest user could use this flaw to crash the host or, potentially,
escalate their privileges, allowing them to execute arbitrary code at
the host kernel level. (CVE-2013-1796, Important)

* A potential use-after-free flaw was found in the way KVM handled
guest time updates when the GPA (guest physical address) the guest
registered by writing to the MSR_KVM_SYSTEM_TIME machine state
register (MSR) fell into a movable or removable memory region of the
hosting user-space process (by default, QEMU-KVM) on the host. If that
memory region is deregistered from KVM using
KVM_SET_USER_MEMORY_REGION and the allocated virtual memory reused, a
privileged guest user could potentially use this flaw to escalate
their privileges on the host. (CVE-2013-1797, Important)

* A flaw was found in the way KVM emulated IOAPIC (I/O Advanced
Programmable Interrupt Controller). A missing validation check in the
ioapic_read_indirect() function could allow a privileged guest user to
crash the host, or read a substantial portion of host kernel memory.
(CVE-2013-1798, Important)

* A race condition in install_user_keyrings(), leading to a NULL
pointer dereference, was found in the key management facility. A
local, unprivileged user could use this flaw to cause a denial of
service. (CVE-2013-1792, Moderate)

* A NULL pointer dereference in the XFRM implementation could allow a
local user who has the CAP_NET_ADMIN capability to cause a denial of
service. (CVE-2013-1826, Moderate)

* A NULL pointer dereference in the Datagram Congestion Control
Protocol (DCCP) implementation could allow a local user to cause a
denial of service. (CVE-2013-1827, Moderate)

* Information leak flaws in the XFRM implementation could allow a
local user who has the CAP_NET_ADMIN capability to leak kernel stack
memory to user-space. (CVE-2012-6537, Low)

* Two information leak flaws in the Asynchronous Transfer Mode (ATM)
subsystem could allow a local, unprivileged user to leak kernel stack
memory to user-space. (CVE-2012-6546, Low)

* An information leak was found in the TUN/TAP device driver in the
networking implementation. A local user with access to a TUN/TAP
virtual interface could use this flaw to leak kernel stack memory to
user-space. (CVE-2012-6547, Low)

* An information leak in the Bluetooth implementation could allow a
local user who has the CAP_NET_ADMIN capability to leak kernel stack
memory to user-space. (CVE-2013-0349, Low)

* A use-after-free flaw was found in the tmpfs implementation. A local
user able to mount and unmount a tmpfs file system could use this flaw
to cause a denial of service or, potentially, escalate their
privileges. (CVE-2013-1767, Low)

* A NULL pointer dereference was found in the Linux kernel's USB
Inside Out Edgeport Serial Driver implementation. An attacker with
physical access to a system could use this flaw to cause a denial of
service. (CVE-2013-1774, Low)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1304&L=scientific-linux-errata&T=0&P=2206
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77bdac8b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/25");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-358.6.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-358.6.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-358.6.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-358.6.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-358.6.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-358.6.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-358.6.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-358.6.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-358.6.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-358.6.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-358.6.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-358.6.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-358.6.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-358.6.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-358.6.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

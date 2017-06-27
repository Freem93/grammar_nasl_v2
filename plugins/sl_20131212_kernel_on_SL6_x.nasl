#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(71491);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/12/17 11:43:42 $");

  script_cve_id("CVE-2013-2141", "CVE-2013-4470", "CVE-2013-6367", "CVE-2013-6368");

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
"* A flaw was found in the way the Linux kernel's TCP/IP protocol suite
implementation handled sending of certain UDP packets over sockets
that used the UDP_CORK option when the UDP Fragmentation Offload (UFO)
feature was enabled on the output device. A local, unprivileged user
could use this flaw to cause a denial of service or, potentially,
escalate their privileges on the system. (CVE-2013-4470, Important)

* A divide-by-zero flaw was found in the apic_get_tmcct() function in
KVM's Local Advanced Programmable Interrupt Controller (LAPIC)
implementation. A privileged guest user could use this flaw to crash
the host. (CVE-2013-6367, Important)

* A memory corruption flaw was discovered in the way KVM handled
virtual APIC accesses that crossed a page boundary. A local,
unprivileged user could use this flaw to crash the system or,
potentially, escalate their privileges on the system. (CVE-2013-6368,
Important)

* An information leak flaw in the Linux kernel could allow a local,
unprivileged user to leak kernel memory to user space. (CVE-2013-2141,
Low)

This update also fixes several bugs and adds two enhancements.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=4929
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34eff070"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/17");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-431.1.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-431.1.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-431.1.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-431.1.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-431.1.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-431.1.2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-431.1.2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-431.1.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-431.1.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-431.1.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-431.1.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-431.1.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-431.1.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-431.1.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-431.1.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-431.1.2.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

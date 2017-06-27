#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60929);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2010-3432", "CVE-2010-3442", "CVE-2010-3699", "CVE-2010-3858", "CVE-2010-3859", "CVE-2010-3865", "CVE-2010-3876", "CVE-2010-3880", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4161", "CVE-2010-4242", "CVE-2010-4247", "CVE-2010-4248");

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

  - A flaw was found in sctp_packet_config() in the Linux
    kernel's Stream Control Transmission Protocol (SCTP)
    implementation. A remote attacker could use this flaw to
    cause a denial of service. (CVE-2010-3432, Important)

  - A missing integer overflow check was found in
    snd_ctl_new() in the Linux kernel's sound subsystem. A
    local, unprivileged user on a 32-bit system could use
    this flaw to cause a denial of service or escalate their
    privileges. (CVE-2010-3442, Important)

  - A heap overflow flaw in the Linux kernel's Transparent
    Inter-Process Communication protocol (TIPC)
    implementation could allow a local, unprivileged user to
    escalate their privileges. (CVE-2010-3859, Important)

  - An integer overflow flaw was found in the Linux kernel's
    Reliable Datagram Sockets (RDS) protocol implementation.
    A local, unprivileged user could use this flaw to cause
    a denial of service or escalate their privileges.
    (CVE-2010-3865, Important)

  - A flaw was found in the Xenbus code for the unified
    block-device I/O interface back end. A privileged guest
    user could use this flaw to cause a denial of service on
    the host system running the Xen hypervisor.
    (CVE-2010-3699, Moderate)

  - Missing sanity checks were found in setup_arg_pages() in
    the Linux kernel. When making the size of the argument
    and environment area on the stack very large, it could
    trigger a BUG_ON(), resulting in a local denial of
    service. (CVE-2010-3858, Moderate)

  - A flaw was found in inet_csk_diag_dump() in the Linux
    kernel's module for monitoring the sockets of INET
    transport protocols. By sending a netlink message with
    certain bytecode, a local, unprivileged user could cause
    a denial of service. (CVE-2010-3880, Moderate)

  - Missing sanity checks were found in gdth_ioctl_alloc()
    in the gdth driver in the Linux kernel. A local user
    with access to '/dev/gdth' on a 64-bit system could use
    this flaw to cause a denial of service or escalate their
    privileges. (CVE-2010-4157, Moderate)

  - The fix put into kernel-2.6.18-164.el5 introduced a
    regression. A local, unprivileged user could use this
    flaw to cause a denial of service. (CVE-2010-4161,
    Moderate)

  - A NULL pointer dereference flaw was found in the
    Bluetooth HCI UART driver in the Linux kernel. A local,
    unprivileged user could use this flaw to cause a denial
    of service. (CVE-2010-4242, Moderate)

  - It was found that a malicious guest running on the Xen
    hypervisor could place invalid data in the memory that
    the guest shared with the blkback and blktap back-end
    drivers, resulting in a denial of service on the host
    system. (CVE-2010-4247, Moderate)

  - A flaw was found in the Linux kernel's CPU time clocks
    implementation for the POSIX clock interface. A local,
    unprivileged user could use this flaw to cause a denial
    of service. (CVE-2010-4248, Moderate)

  - Missing initialization flaws in the Linux kernel could
    lead to information leaks. (CVE-2010-3876,
    CVE-2010-4083, Low)

This update also fixes several bugs and adds an enhancement.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1101&L=scientific-linux-errata&T=0&P=78
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?11870ede"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-194.32.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-194.32.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-194.32.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-194.32.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-194.32.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-194.32.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-194.32.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kernel-headers-2.6.18-194.32.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-194.32.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-194.32.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

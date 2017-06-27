#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61041);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:26 $");

  script_cve_id("CVE-2010-4251", "CVE-2011-0999", "CVE-2011-1010", "CVE-2011-1023", "CVE-2011-1082", "CVE-2011-1090", "CVE-2011-1163", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1494", "CVE-2011-1581");

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

This update fixes the following security issues :

  - Multiple buffer overflow flaws were found in the Linux
    kernel's Management Module Support for Message Passing
    Technology (MPT) based controllers. A local,
    unprivileged user could use these flaws to cause a
    denial of service, an information leak, or escalate
    their privileges. (CVE-2011-1494, CVE-2011-1495,
    Important)

  - A flaw was found in the Linux kernel's Ethernet bonding
    driver implementation. Packets coming in from network
    devices that have more than 16 receive queues to a
    bonding interface could cause a denial of service.
    (CVE-2011-1581, Important)

  - A flaw was found in the Linux kernel's networking
    subsystem. If the number of packets received exceeded
    the receiver's buffer limit, they were queued in a
    backlog, consuming memory, instead of being discarded. A
    remote attacker could abuse this flaw to cause a denial
    of service (out-of-memory condition). (CVE-2010-4251,
    Moderate)

  - A flaw was found in the Linux kernel's Transparent Huge
    Pages (THP) implementation. A local, unprivileged user
    could abuse this flaw to allow the user stack (when it
    is using huge pages) to grow and cause a denial of
    service. (CVE-2011-0999, Moderate)

  - A flaw was found in the transmit methods (xmit) for the
    loopback and InfiniBand transports in the Linux kernel's
    Reliable Datagram Sockets (RDS) implementation. A local,
    unprivileged user could use this flaw to cause a denial
    of service. (CVE-2011-1023, Moderate)

  - A flaw in the Linux kernel's Event Poll (epoll)
    implementation could allow a local, unprivileged user to
    cause a denial of service. (CVE-2011-1082, Moderate)

  - An inconsistency was found in the interaction between
    the Linux kernel's method for allocating NFSv4 (Network
    File System version 4) ACL data and the method by which
    it was freed. This inconsistency led to a kernel panic
    which could be triggered by a local, unprivileged user
    with files owned by said user on an NFSv4 share.
    (CVE-2011-1090, Moderate)

  - A missing validation check was found in the Linux
    kernel's mac_partition() implementation, used for
    supporting file systems created on Mac OS operating
    systems. A local attacker could use this flaw to cause a
    denial of service by mounting a disk that contains
    specially crafted partitions. (CVE-2011-1010, Low)

  - A buffer overflow flaw in the DEC Alpha OSF partition
    implementation in the Linux kernel could allow a local
    attacker to cause an information leak by mounting a disk
    that contains specially crafted partition tables.
    (CVE-2011-1163, Low)

  - Missing validations of null-terminated string data
    structure elements in the do_replace(),
    compat_do_replace(), do_ipt_get_ctl(),
    do_ip6t_get_ctl(), and do_arpt_get_ctl() functions could
    allow a local user who has the CAP_NET_ADMIN capability
    to cause an information leak. (CVE-2011-1170,
    CVE-2011-1171, CVE-2011-1172, Low)

This update also fixes several hundred bugs and adds enhancements.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1106&L=scientific-linux-errata&T=0&P=2604
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb3b776a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-131.0.15.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-131.0.15.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-131.0.15.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-131.0.15.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-131.0.15.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-131.0.15.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-131.0.15.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-131.0.15.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-131.0.15.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-131.0.15.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-131.0.15.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-131.0.15.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-131.0.15.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

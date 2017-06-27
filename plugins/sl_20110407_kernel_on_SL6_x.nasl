#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61012);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2010-3296", "CVE-2010-4346", "CVE-2010-4526", "CVE-2010-4648", "CVE-2010-4655", "CVE-2010-4656", "CVE-2011-0521", "CVE-2011-0695", "CVE-2011-0710", "CVE-2011-0716", "CVE-2011-1478");

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
"This update fixes the following security issues :

  - A flaw was found in the sctp_icmp_proto_unreachable()
    function in the Linux kernel's Stream Control
    Transmission Protocol (SCTP) implementation. A remote
    attacker could use this flaw to cause a denial of
    service. (CVE-2010-4526, Important)

  - A missing boundary check was found in the dvb_ca_ioctl()
    function in the Linux kernel's av7110 module. On systems
    that use old DVB cards that require the av7110 module, a
    local, unprivileged user could use this flaw to cause a
    denial of service or escalate their privileges.
    (CVE-2011-0521, Important)

  - A race condition was found in the way the Linux kernel's
    InfiniBand implementation set up new connections. This
    could allow a remote user to cause a denial of service.
    (CVE-2011-0695, Important)

  - A heap overflow flaw in the iowarrior_write() function
    could allow a user with access to an IO-Warrior USB
    device, that supports more than 8 bytes per report, to
    cause a denial of service or escalate their privileges.
    (CVE-2010-4656, Moderate)

  - A flaw was found in the way the Linux Ethernet bridge
    implementation handled certain IGMP (Internet Group
    Management Protocol) packets. A local, unprivileged user
    on a system that has a network interface in an Ethernet
    bridge could use this flaw to crash that system
    (CVE-2011-0716, Moderate)

  - A NULL pointer dereference flaw was found in the Generic
    Receive Offload (GRO) functionality in the Linux
    kernel's networking implementation. If both GRO and
    promiscuous mode were enabled on an interface in a
    virtual LAN (VLAN), it could result in a denial of
    service when a malformed VLAN frame is received on that
    interface. (CVE-2011-1478, Moderate)

  - A missing initialization flaw in the Linux kernel could
    lead to an information leak. (CVE-2010-3296, Low)

  - A missing security check in the Linux kernel's
    implementation of the install_special_mapping() function
    could allow a local, unprivileged user to bypass the
    mmap_min_addr protection mechanism. (CVE-2010-4346, Low)

  - A logic error in the orinoco_ioctl_set_auth() function
    in the Linux kernel's ORiNOCO wireless extensions
    support implementation could render TKIP countermeasures
    ineffective when it is enabled, as it enabled the card
    instead of shutting it down. (CVE-2010-4648, Low)

  - A missing initialization flaw was found in the
    ethtool_get_regs() function in the Linux kernel's
    ethtool IOCTL handler. A local user who has the
    CAP_NET_ADMIN capability could use this flaw to cause an
    information leak. (CVE-2010-4655, Low)

  - An information leak was found in the Linux kernel's
    task_show_regs() implementation. On IBM S/390 systems, a
    local, unprivileged user could use this flaw to read
    /proc/[PID]/status files, allowing them to discover the
    CPU register values of processes. (CVE-2011-0710, Low)

This update also fixes several bugs.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1104&L=scientific-linux-errata&T=0&P=1338
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f89f369"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/07");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-71.24.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-71.24.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-71.24.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-71.24.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-71.24.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-71.24.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-71.24.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-71.24.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

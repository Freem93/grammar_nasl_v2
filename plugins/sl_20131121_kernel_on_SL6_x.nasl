#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(71490);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/12/17 11:43:42 $");

  script_cve_id("CVE-2012-2375", "CVE-2012-6542", "CVE-2012-6545", "CVE-2013-0343", "CVE-2013-1928", "CVE-2013-1929", "CVE-2013-2164", "CVE-2013-2234", "CVE-2013-2851", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2892", "CVE-2013-3231", "CVE-2013-4345", "CVE-2013-4387", "CVE-2013-4591", "CVE-2013-4592");

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

  - A flaw was found in the way the Linux kernel's IPv6
    implementation handled certain UDP packets when the UDP
    Fragmentation Offload (UFO) feature was enabled. A
    remote attacker could use this flaw to crash the system
    or, potentially, escalate their privileges on the
    system. (CVE-2013-4387, Important)

  - A flaw was found in the way the Linux kernel handled the
    creation of temporary IPv6 addresses. If the IPv6
    privacy extension was enabled
    (/proc/sys/net/ipv6/conf/eth0/use_tempaddr set to '2'),
    an attacker on the local network could disable IPv6
    temporary address generation, leading to a potential
    information disclosure. (CVE-2013-0343, Moderate)

  - A flaw was found in the way the Linux kernel handled HID
    (Human Interface Device) reports with an out-of-bounds
    Report ID. An attacker with physical access to the
    system could use this flaw to crash the system or,
    potentially, escalate their privileges on the system.
    (CVE-2013-2888, Moderate)

  - An off-by-one flaw was found in the way the ANSI CPRNG
    implementation in the Linux kernel processed non-block
    size aligned requests. This could lead to random numbers
    being generated with less bits of entropy than expected
    when ANSI CPRNG was used. (CVE-2013-4345, Moderate)

  - It was found that the fix for CVE-2012-2375 released via
    SLSA-2012:1580 accidentally removed a check for
    small-sized result buffers. A local, unprivileged user
    with access to an NFSv4 mount with ACL support could use
    this flaw to crash the system or, potentially, escalate
    their privileges on the system . (CVE-2013-4591,
    Moderate)

  - A flaw was found in the way IOMMU memory mappings were
    handled when moving memory slots. A malicious user on a
    KVM host who has the ability to assign a device to a
    guest could use this flaw to crash the host.
    (CVE-2013-4592, Moderate)

  - Heap-based buffer overflow flaws were found in the way
    the Zeroplus and Pantherlord/GreenAsia game controllers
    handled HID reports. An attacker with physical access to
    the system could use these flaws to crash the system or,
    potentially, escalate their privileges on the system.
    (CVE-2013-2889, CVE-2013-2892, Moderate)

  - Two information leak flaws were found in the logical
    link control (LLC) implementation in the Linux kernel. A
    local, unprivileged user could use these flaws to leak
    kernel stack memory to user space. (CVE-2012-6542,
    CVE-2013-3231, Low)

  - A heap-based buffer overflow in the way the tg3 Ethernet
    driver parsed the vital product data (VPD) of devices
    could allow an attacker with physical access to a system
    to cause a denial of service or, potentially, escalate
    their privileges. (CVE-2013-1929, Low)

  - Information leak flaws in the Linux kernel could allow a
    privileged, local user to leak kernel memory to user
    space. (CVE-2012-6545, CVE-2013-1928, CVE-2013-2164,
    CVE-2013-2234, Low)

  - A format string flaw was found in the Linux kernel's
    block layer. A privileged, local user could potentially
    use this flaw to escalate their privileges to kernel
    level (ring0). (CVE-2013-2851, Low)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=4785
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9ea222cb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-431.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-431.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-431.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-431.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-431.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-431.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-431.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-431.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-431.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-431.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-431.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-431.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-431.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-431.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-431.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-431.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

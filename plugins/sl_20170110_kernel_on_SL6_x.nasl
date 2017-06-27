#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(96481);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/13 14:56:01 $");

  script_cve_id("CVE-2016-4998", "CVE-2016-6828", "CVE-2016-7117");

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
"Security Fix(es) :

  - A use-after-free vulnerability was found in the kernels
    socket recvmmsg subsystem. This may allow remote
    attackers to corrupt memory and may allow execution of
    arbitrary code. This corruption takes place during the
    error handling routines within __sys_recvmmsg()
    function. (CVE-2016-7117, Important)

  - An out-of-bounds heap memory access leading to a Denial
    of Service, heap disclosure, or further impact was found
    in setsockopt(). The function call is normally
    restricted to root, however some processes with
    cap_sys_admin may also be able to trigger this flaw in
    privileged container environments. (CVE-2016-4998,
    Moderate)

  - A use-after-free vulnerability was found in
    tcp_xmit_retransmit_queue and other tcp_* functions.
    This condition could allow an attacker to send an
    incorrect selective acknowledgment to existing
    connections, possibly resetting a connection.
    (CVE-2016-6828, Moderate)

Bug Fix(es) :

  - When parallel NFS returned a file layout, a kernel crash
    sometimes occurred. This update removes the call to the
    BUG_ON() function from a code path of a client that
    returns the file layout. As a result, the kernel no
    longer crashes in the described situation.

  - When a guest virtual machine (VM) on Microsoft Hyper-V
    was set to crash on a Nonmaskable Interrupt (NMI) that
    was injected from the host, this VM became unresponsive
    and did not create the vmcore dump file. This update
    applies a set of patches to the Virtual Machine Bus
    kernel driver (hv_vmbus) that fix this bug. As a result,
    the VM now first creates and saves the vmcore dump file
    and then reboots.

  - From Scientific Linux 6.6 to 6.8, the IPv6 routing cache
    occasionally showed incorrect values. This update fixes
    the DST_NOCOUNT mechanism, and the IPv6 routing cache
    now shows correct values.

  - When using the ixgbe driver and the software Fibre
    Channel over Ethernet (FCoE) stack, suboptimal
    performance in some cases occurred on systems with a
    large number of CPUs. This update fixes the
    fc_exch_alloc() function to try all the available
    exchange managers in the list for an available exchange
    ID. This change avoids failing allocations, which
    previously led to the host busy status.

  - When the vmwgfx kernel module loads, it overrides the
    boot resolution automatically. Consequently, users were
    not able to change the resolution by manual setting of
    the kernel's 'vga=' parameter in the
    /boot/grub/grub.conf file. This update adds the
    'nomodeset' parameter, which can be set in the
    /boot/grub/grub.conf file. The 'nomodeset' parameter
    allows the users to prevent the vmwgfx driver from
    loading. As a result, the setting of the 'vga='
    parameter works as expected, in case that vmwgfx does
    not load.

  - When Scientific Linux 6.8 was booted on SMBIOS 3.0 based
    systems, Desktop Management Interface (DMI) information,
    which is referenced by several applications, such as NEC
    server's memory RAS utility, was missing entries in the
    sysfs virtual file system. This update fixes the
    underlying source code, and sysfs now shows the DMI
    information as expected.

  - Previously, bonding mode active backup and the
    propagation of the media access control (MAC) address to
    a VLAN interface did not work in Scientific Linux 6.8,
    when the fail_over_mac bonding parameter was set to
    fail_over_mac=active. With this update, the underlying
    source code has been fixed so that the VLANs continue
    inheriting the MAC address of the active physical
    interface until the VLAN MAC address is explicitly set
    to any value. As a result, IPv6 EUI64 addresses for the
    VLAN can reflect any changes to the MAC address of the
    physical interface, and Duplicate Address Detection
    (DAD) behaves as expected."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1701&L=scientific-linux-errata&F=&S=&P=3224
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67218412"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-common-i686-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-642.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-642.13.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

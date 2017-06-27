#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61331);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_cve_id("CVE-2012-0044", "CVE-2012-1179", "CVE-2012-2119", "CVE-2012-2121", "CVE-2012-2123", "CVE-2012-2136", "CVE-2012-2137", "CVE-2012-2372", "CVE-2012-2373");

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

  - A local, unprivileged user could use an integer overflow
    flaw in drm_mode_dirtyfb_ioctl() to cause a denial of
    service or escalate their privileges. (CVE-2012-0044,
    Important)

  - A buffer overflow flaw was found in the macvtap device
    driver, used for creating a bridged network between the
    guest and the host in KVM (Kernel-based Virtual Machine)
    environments. A privileged guest user in a KVM guest
    could use this flaw to crash the host. Note: This issue
    only affected hosts that have the vhost_net module
    loaded with the experimental_zcopytx module option
    enabled (it is not enabled by default), and that also
    have macvtap configured for at least one guest.
    (CVE-2012-2119, Important)

  - When a set user ID (setuid) application is executed,
    certain personality flags for controlling the
    application's behavior are cleared (that is, a
    privileged application will not be affected by those
    flags). It was found that those flags were not cleared
    if the application was made privileged via file system
    capabilities. A local, unprivileged user could use this
    flaw to change the behavior of such applications,
    allowing them to bypass intended restrictions. Note that
    for default installations, no application shipped by us
    for Scientific Linux is made privileged via file system
    capabilities. (CVE-2012-2123, Important)

  - It was found that the data_len parameter of the
    sock_alloc_send_pskb() function in the Linux kernel's
    networking implementation was not validated before use.
    A privileged guest user in a KVM guest could use this
    flaw to crash the host or, possibly, escalate their
    privileges on the host. (CVE-2012-2136, Important)

  - A buffer overflow flaw was found in the
    setup_routing_entry() function in the KVM subsystem of
    the Linux kernel in the way the Message Signaled
    Interrupts (MSI) routing entry was handled. A local,
    unprivileged user could use this flaw to cause a denial
    of service or, possibly, escalate their privileges.
    (CVE-2012-2137, Important)

  - A race condition was found in the Linux kernel's memory
    management subsystem in the way pmd_none_or_clear_bad(),
    when called with mmap_sem in read mode, and Transparent
    Huge Pages (THP) page faults interacted. A privileged
    user in a KVM guest with the ballooning functionality
    enabled could potentially use this flaw to crash the
    host. A local, unprivileged user could use this flaw to
    crash the system. (CVE-2012-1179, Moderate)

  - A flaw was found in the way device memory was handled
    during guest device removal. Upon successful device
    removal, memory used by the device was not properly
    unmapped from the corresponding IOMMU or properly
    released from the kernel, leading to a memory leak. A
    malicious user on a KVM host who has the ability to
    assign a device to a guest could use this flaw to crash
    the host. (CVE-2012-2121, Moderate)

  - A flaw was found in the Linux kernel's Reliable Datagram
    Sockets (RDS) protocol implementation. A local,
    unprivileged user could use this flaw to cause a denial
    of service. (CVE-2012-2372, Moderate)

  - A race condition was found in the Linux kernel's memory
    management subsystem in the way pmd_populate() and
    pte_offset_map_lock() interacted on 32-bit x86 systems
    with more than 4GB of RAM. A local, unprivileged user
    could use this flaw to cause a denial of service.
    (CVE-2012-2373, Moderate)

This update also fixes several bugs.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1206&L=scientific-linux-errata&T=0&P=2223
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09fe3653"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/18");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-220.23.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-220.23.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-220.23.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-220.23.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-220.23.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-220.23.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-220.23.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-220.23.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-220.23.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-220.23.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-220.23.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-220.23.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-220.23.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-220.23.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-220.23.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

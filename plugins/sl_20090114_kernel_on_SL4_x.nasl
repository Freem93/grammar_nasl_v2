#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60520);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-3275", "CVE-2008-4933", "CVE-2008-4934", "CVE-2008-5025", "CVE-2008-5029", "CVE-2008-5300", "CVE-2008-5702");

  script_name(english:"Scientific Linux Security Update : kernel on SL4.x i386/x86_64");
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
"This update addresses the following security issues :

  - the sendmsg() function in the Linux kernel did not block
    during UNIX socket garbage collection. This could,
    potentially, lead to a local denial of service.
    (CVE-2008-5300, Important)

  - when fput() was called to close a socket, the
    __scm_destroy() function in the Linux kernel could make
    indirect recursive calls to itself. This could,
    potentially, lead to a local denial of service.
    (CVE-2008-5029, Important)

  - a deficiency was found in the Linux kernel virtual file
    system (VFS) implementation. This could allow a local,
    unprivileged user to make a series of file creations
    within deleted directories, possibly causing a denial of
    service. (CVE-2008-3275, Moderate)

  - a buffer underflow flaw was found in the Linux kernel
    IB700 SBC watchdog timer driver. This deficiency could
    lead to a possible information leak. By default, the
    '/dev/watchdog' device is accessible only to the root
    user. (CVE-2008-5702, Low)

  - the hfs and hfsplus file systems code failed to properly
    handle corrupted data structures. This could,
    potentially, lead to a local denial of service.
    (CVE-2008-4933, CVE-2008-5025, Low)

  - a flaw was found in the hfsplus file system
    implementation. This could, potentially, lead to a local
    denial of service when write operations were performed.
    (CVE-2008-4934, Low)

This update also fixes the following bugs :

  - when running Red Hat Enterprise Linux 4.6 and 4.7 on
    some systems running Intel&reg; CPUs, the cpuspeed
    daemon did not run, preventing the CPU speed from being
    changed, such as not being reduced to an idle state when
    not in use.

  - mmap() could be used to gain access to beyond the first
    megabyte of RAM, due to insufficient checks in the Linux
    kernel code. Checks have been added to prevent this.

  - attempting to turn keyboard LEDs on and off rapidly on
    keyboards with slow keyboard controllers, may have
    caused key presses to fail.

  - after migrating a hypervisor guest, the MAC address
    table was not updated, causing packet loss and
    preventing network connections to the guest. Now, a
    gratuitous ARP request is sent after migration. This
    refreshes the ARP caches, minimizing network downtime.

  - writing crash dumps with diskdump may have caused a
    kernel panic on Non-Uniform Memory Access (NUMA) systems
    with certain memory configurations.

  - on big-endian systems, such as PowerPC, the getsockopt()
    function incorrectly returned 0 depending on the
    parameters passed to it when the time to live (TTL)
    value equaled 255, possibly causing memory corruption
    and application crashes.

  - a problem in the kernel packages provided by the
    RHSA-2008:0508 advisory caused the Linux kernel's
    built-in memory copy procedure to return the wrong error
    code after recovering from a page fault on AMD64 and
    Intel 64 systems. This may have caused other Linux
    kernel functions to return wrong error codes.

  - a divide-by-zero bug in the Linux kernel process
    scheduler, which may have caused kernel panics on
    certain systems, has been resolved.

  - the netconsole kernel module caused the Linux kernel to
    hang when slave interfaces of bonded network interfaces
    were started, resulting in a system hang or kernel panic
    when restarting the network.

  - the '/proc/xen/' directory existed even if systems were
    not running Red Hat Virtualization. This may have caused
    problems for third-party software that checks
    virtualization-ability based on the existence of
    '/proc/xen/'. Note: this update will remove the
    '/proc/xen/' directory on systems not running Red Hat
    Virtualization.

This updated kernel-utils package adds an enhancement in the way of
proper support for user-space frequency-scaling on multi-core systems."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0901&L=scientific-linux-errata&T=0&P=1314
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72598625"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-utils-2.4-14.1.117.2.1")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-78.0.13.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

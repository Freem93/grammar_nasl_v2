#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60609);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2009-1072", "CVE-2009-1192", "CVE-2009-1336", "CVE-2009-1337", "CVE-2009-1385", "CVE-2009-1630", "CVE-2009-1758");

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
"These updated packages fix the following security issues :

  - the exit_notify() function in the Linux kernel did not
    properly reset the exit signal if a process executed a
    set user ID (setuid) application before exiting. This
    could allow a local, unprivileged user to elevate their
    privileges. (CVE-2009-1337, Important)

  - the Linux kernel implementation of the Network File
    System (NFS) did not properly initialize the file name
    limit in the nfs_server data structure. This flaw could
    possibly lead to a denial of service on a client
    mounting an NFS share. (CVE-2009-1336, Moderate)

  - a flaw was found in the Intel PRO/1000 network driver in
    the Linux kernel. Frames with sizes near the MTU of an
    interface may be split across multiple hardware receive
    descriptors. Receipt of such a frame could leak through
    a validation check, leading to a corruption of the
    length check. A remote attacker could use this flaw to
    send a specially crafted packet that would cause a
    denial of service. (CVE-2009-1385, Important)

  - the Linux kernel Network File System daemon (nfsd)
    implementation did not drop the CAP_MKNOD capability
    when handling requests from local, unprivileged users.
    This flaw could possibly lead to an information leak or
    privilege escalation. (CVE-2009-1072, Moderate)

  - Frank Filz reported the NFSv4 client was missing a file
    permission check for the execute bit in some situations.
    This could allow local, unprivileged users to run
    non-executable files on NFSv4 mounted file systems.
    (CVE-2009-1630, Moderate)

  - a missing check was found in the hypervisor_callback()
    function in the Linux kernel provided by the kernel-xen
    package. This could cause a denial of service of a
    32-bit guest if an application running in that guest
    accesses a certain memory location in the kernel.
    (CVE-2009-1758, Moderate)

  - a flaw was found in the AGPGART driver. The
    agp_generic_alloc_page() and agp_generic_alloc_pages()
    functions did not zero out the memory pages they
    allocate, which may later be available to user-space
    processes. This flaw could possibly lead to an
    information leak. (CVE-2009-1192, Low)

These updated packages also fix the following bugs :

  - '/proc/[pid]/maps' and '/proc/[pid]/smaps' can only be
    read by processes able to use the ptrace() call on a
    given process; however, certain information from
    '/proc/[pid]/stat' and '/proc/[pid]/wchan' could be used
    to reconstruct memory maps, making it possible to bypass
    the Address Space Layout Randomization (ASLR) security
    feature. This update addresses this issue. (BZ#499549)

  - in some situations, the link count was not decreased
    when renaming unused files on NFS mounted file systems.
    This may have resulted in poor performance. With this
    update, the link count is decreased in these situations,
    the same as is done for other file operations, such as
    unlink and rmdir. (BZ#501802)

  - tcp_ack() cleared the probes_out variable even if there
    were outstanding packets. When low TCP keepalive
    intervals were used, this bug may have caused problems,
    such as connections terminating, when using remote tools
    such as rsh and rlogin. (BZ#501754)

  - off-by-one errors in the time normalization code could
    have caused clock_gettime() to return one billion
    nanoseconds, rather than adding an extra second. This
    bug could have caused the name service cache daemon
    (nscd) to consume excessive CPU resources. (BZ#501800)

  - a system panic could occur when one thread read
    '/proc/bus/input/devices' while another was removing a
    device. With this update, a mutex has been added to
    protect the input_dev_list and input_handler_list
    variables, which resolves this issue. (BZ#501804)

  - using netdump may have caused a kernel deadlock on some
    systems. (BZ#504565)

  - the file system mask, which lists capabilities for users
    with a file system user ID (fsuid) of 0, was missing the
    CAP_MKNOD and CAP_LINUX_IMMUTABLE capabilities. This
    could, potentially, allow users with an fsuid other than
    0 to perform actions on some file system types that
    would otherwise be prevented. This update adds these
    capabilities. (BZ#497269)

Kernel Feature Support :

  - added a new allowable value to
    '/proc/sys/kernel/wake_balance' to allow the scheduler
    to run the thread on any available CPU rather than
    scheduling it on the optimal CPU.

  - added 'max_writeback_pages' tunable parameter to
    /proc/sys/vm/ to allow the maximum number of modified
    pages kupdate writes to disk, per iteration per run.

  - added 'swap_token_timeout' tunable parameter to
    /proc/sys/vm/ to provide a valid hold time for the swap
    out protection token.

  - added diskdump support to sata_svw driver.

  - limited physical memory to 64GB for 32-bit kernels
    running on systems with more than 64GB of physical
    memory to prevent boot failures.

  - improved reliability of autofs.

  - added support for 'rdattr_error' in NFSv4 readdir
    requests.

  - fixed various short packet handling issues for NFSv4
    readdir and sunrpc.

  - fixed several CIFS bugs.

Networking and IPv6 Enablement :

  - added router solicitation support.

  - enforced sg requires tx csum in ethtool.

Platform Support :

x86, AMD64, Intel 64

  - added support for a new Intel chipset.

  - added initialization vendor info in boot_cpu_data.

  - added support for N_Port ID Virtualization (NPIV) for
    IBM System z guests using zFCP.

  - added HDMI support for some AMD and ATI chipsets.

  - updated HDA driver in ALSA to latest upstream as of
    2008-07-22.

  - added support for affected_cpus for cpufreq.

  - removed polling timer from i8042.

  - fixed PM-Timer when using the ASUS A8V Deluxe
    motherboard.

  - backported usbfs_mutex in usbfs.

Network Driver Updates :

  - updated forcedeth driver to latest upstream version
    0.61.

  - fixed various e1000 issues when using Intel ESB2
    hardware.

  - updated e1000e driver to upstream version 0.3.3.3-k6.

  - updated igb to upstream version 1.2.45-k2.

  - updated tg3 to upstream version 3.96.

  - updated ixgbe to upstream version 1.3.18-k4.

  - updated bnx2 to upstream version 1.7.9.

  - updated bnx2x to upstream version 1.45.23.

  - fixed bugs and added enhancements for the NetXen NX2031
    and NX3031 products.

  - updated Realtek r8169 driver to support newer network
    chipsets. All variants of RTL810x/RTL8168(9) are now
    supported.

Storage Driver Updates :

  - fixed various SCSI issues. Also, the SCSI sd driver now
    calls the revalidate_disk wrapper.

  - fixed a dmraid reduced I/O delay bug in certain
    configurations.

  - removed quirk aac_quirk_scsi_32 for some aacraid
    controllers.

  - updated FCP driver on IBM System z systems with support
    for point-to-point connections.

  - updated lpfc to version 8.0.16.46.

  - updated megaraid_sas to version 4.01-RH1.

  - updated MPT Fusion driver to version 3.12.29.00rh.

  - updated qla2xxx firmware to 4.06.01 for 4GB/s and 8GB/s
    adapters.

  - updated qla2xxx driver to version 8.02.09.00.04.08-d.

  - fixed sata_nv in libsata to disable ADMA mode by
    default.

Miscellaneous Updates :

  - upgraded OpenFabrics Alliance Enterprise Distribution
    (OFED) to version 1.4.

  - added driver support and fixes for various Wacom
    tablets.

Note: The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0907&L=scientific-linux-errata&T=0&P=75
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb7cb543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=497269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=499549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=501754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=501800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=501802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=501804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=504565"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(16, 20, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/30");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-89.0.3.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-89.0.3.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-89.0.3.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-largesmp-2.6.9-89.0.3.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-largesmp-devel-2.6.9-89.0.3.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-89.0.3.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-89.0.3.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-89.0.3.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-89.0.3.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

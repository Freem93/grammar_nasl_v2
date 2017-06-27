#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60532);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-4933", "CVE-2008-4934", "CVE-2008-5025", "CVE-2008-5029", "CVE-2008-5079", "CVE-2008-5182", "CVE-2008-5713", "CVE-2009-0031", "CVE-2009-0065");

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
"This update addresses the following security issues :

  - a memory leak in keyctl handling. A local user could use
    this flaw to deplete kernel memory, eventually leading
    to a denial of service. (CVE-2009-0031, Important)

  - a buffer overflow in the Linux kernel Partial Reliable
    Stream Control Transmission Protocol (PR-SCTP)
    implementation. This could, potentially, lead to a
    denial of service if a Forward-TSN chunk is received
    with a large stream ID. (CVE-2009-0065, Important)

  - a flaw when handling heavy network traffic on an SMP
    system with many cores. An attacker who could send a
    large amount of network traffic could create a denial of
    service. (CVE-2008-5713, Important)

  - the code for the HFS and HFS Plus (HFS+) file systems
    failed to properly handle corrupted data structures.
    This could, potentially, lead to a local denial of
    service. (CVE-2008-4933, CVE-2008-5025, Low)

  - a flaw was found in the HFS Plus (HFS+) file system
    implementation. This could, potentially, lead to a local
    denial of service when write operations are performed.
    (CVE-2008-4934, Low)

  - when fput() was called to close a socket, the
    __scm_destroy() function in the Linux kernel could make
    indirect recursive calls to itself. This could,
    potentially, lead to a denial of service issue.
    (CVE-2008-5029, Important)

  - a flaw was found in the Asynchronous Transfer Mode (ATM)
    subsystem. A local, unprivileged user could use the flaw
    to listen on the same socket more than once, possibly
    causing a denial of service. (CVE-2008-5079, Important)

  - a race condition was found in the Linux kernel 'inotify'
    watch removal and umount implementation. This could
    allow a local, unprivileged user to cause a privilege
    escalation or a denial of service. (CVE-2008-5182,
    Important)

** Bug fixes and enhancements are provided for :

  - support for specific NICs, including products from the
    following manufacturers: Broadcom Chelsio Cisco Intel
    Marvell NetXen Realtek Sun

  - Fiber Channel support, including support for Qlogic
    qla2xxx, qla4xxx, and qla84xx HBAs and the FCoE, FCP,
    and zFCP protocols.

  - support for various CPUs, including: AMD Opteron
    processors with 45 nm SOI ('Shanghai') AMD Turion Ultra
    processors Cell processors Intel Core i7 processors

  - Xen support, including issues specific to the IA64
    platform, systems using AMD processors, and Dell
    Optiplex GX280 systems

  - ext3, ext4, GFS2, NFS, and SPUFS

  - Infiniband (including eHCA, eHEA, and IPoIB) support

  - common I/O (CIO), direct I/O (DIO), and queued direct
    I/O (qdio) support

  - the kernel distributed lock manager (DLM)

  - hardware issues with: SCSI, IEEE 1394 (FireWire), RAID
    (including issues specific to Adaptec controllers), SATA
    (including NCQ), PCI, audio, serial connections,
    tape-drives, and USB

  - ACPI, some of a general nature and some related to
    specific hardware including: certain Lenovo Thinkpad
    notebooks, HP DC7700 systems, and certain machines based
    on Intel Centrino processor technology.

  - CIFS, including Kerberos support and a tech-preview of
    DFS support

  - networking support, including IPv6, PPPoE, and IPSec

  - support for Intel chipsets, including: Intel Cantiga
    chipsets Intel Eagle Lake chipsets Intel i915 chipsets
    Intel i965 chipsets Intel Ibex Peak chipsets Intel
    chipsets offering QuickPath Interconnects (QPI)

  - device mapping issues, including some in device mapper
    itself

  - various issues specific to IA64 and PPC

  - CCISS, including support for Compaq SMART Array
    controllers P711m and P712m and other new hardware

  - various issues affecting specific HP systems, including:
    DL785G5 XW4800 XW8600 XW8600 XW9400

  - IOMMU support, including specific issues with AMD and
    IBM Calgary hardware

  - the audit subsystem

  - DASD support

  - iSCSI support, including issues specific to Chelsio T3
    adapters

  - LVM issues

  - SCTP management information base (MIB) support

  - issues with: autofs, kdump, kobject_add, libata, lpar,
    ptrace, and utrace

  - platforms using Intel Enhanced Error Handling (EEH)

  - EDAC issues for AMD K8 and Intel i5000

  - ALSA, including support for new hardware

  - futex support

  - hugepage support

  - Intelligent Platform Management Interface (IPMI) support

  - issues affecting NEC/Stratus servers

  - OFED support

  - SELinux

  - various Virtio issues

  - when using the nfsd daemon in a clustered setup, kernel
    panics appeared seemingly at random. These panics were
    caused by a race condition in the device-mapper mirror
    target.

  - the clock_gettime(CLOCK_THREAD_CPUTIME_ID, ) syscall
    returned a smaller timespec value than the result of
    previous clock_gettime() function execution, which
    resulted in a negative, and nonsensical, elapsed time
    value.

  - nfs_create_rpc_client was called with a 'flavor'
    parameter which was usually ignored and ended up
    unconditionally creating the RPC client with an
    AUTH_UNIX flavor. This caused problems on AUTH_GSS
    mounts when the credentials needed to be refreshed. The
    credops did not match the authorization type, which
    resulted in the credops dereferencing an incorrect part
    of the AUTH_UNIX rpc_auth struct.

  - when copy_user_c terminated prematurely due to reading
    beyond the end of the user buffer and the kernel jumped
    to the exception table entry, the rsi register was not
    cleared. This resulted in exiting back to user code with
    garbage in the rsi register.

  - the hexdump data in s390dbf traces was incomplete. The
    length of the data traced was incorrect and the SAN
    payload was read from a different place then it was
    written to.

  - when using connected mode (CM) in IPoIB on ehca2
    hardware, it was not possible to transmit any data.

  - when an application called fork() and pthread_create()
    many times and, at some point, a thread forked a child
    and then attempted to call the setpgid() function, then
    this function failed and returned and ESRCH error value."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0902&L=scientific-linux-errata&T=0&P=2076
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e19b9ae"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 119, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/10");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-128.1.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-128.1.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-128.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-128.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-128.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-128.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-128.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-128.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-128.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-128.1.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

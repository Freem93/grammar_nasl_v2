#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60788);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:08 $");

  script_cve_id("CVE-2010-0307", "CVE-2010-0410", "CVE-2010-0730", "CVE-2010-1085", "CVE-2010-1086");

  script_name(english:"Scientific Linux Security Update : kernel on SL 5.0-5.4 i386/x86_64");
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
"This kernel is already in SL 5.5

This updated contains all the security and bug fixes from the
2.6.18-194.el5 kernel. In additions this update fixes the following
security issues :

  - a flaw was found in the Unidirectional Lightweight
    Encapsulation (ULE) implementation. A remote attacker
    could send a specially crafted ISO MPEG-2 Transport
    Stream (TS) frame to a target system, resulting in an
    infinite loop (denial of service). (CVE-2010-1086,
    Important)

  - on AMD64 systems, it was discovered that the kernel did
    not ensure the ELF interpreter was available before
    making a call to the SET_PERSONALITY macro. A local
    attacker could use this flaw to cause a denial of
    service by running a 32-bit application that attempts to
    execute a 64-bit application. (CVE-2010-0307, Moderate)

  - a flaw was found in the kernel connector implementation.
    A local, unprivileged user could trigger this flaw by
    sending an arbitrary number of notification requests
    using specially crafted netlink messages, resulting in a
    denial of service. (CVE-2010-0410, Moderate)

  - a flaw was found in the Memory-mapped I/O (MMIO)
    instruction decoder in the Xen hypervisor
    implementation. An unprivileged guest user could use
    this flaw to trick the hypervisor into emulating a
    certain instruction, which could crash the guest (denial
    of service). (CVE-2010-0730, Moderate)

  - a divide-by-zero flaw was found in the azx_position_ok()
    function in the driver for Intel High Definition Audio,
    snd-hda-intel. A local, unprivileged user could trigger
    this flaw to cause a kernel crash (denial of service).
    (CVE-2010-1085, Moderate)

This update also fixes the following bugs :

  - in some cases, booting a system with the 'iommu=on'
    kernel parameter resulted in a Xen hypervisor panic.
    (BZ#580199)

  - the fnic driver flushed the Rx queue instead of the Tx
    queue after fabric login. This caused crashes in some
    cases. (BZ#580829)

  - 'kernel unaligned access' warnings were logged to the
    dmesg log on some systems. (BZ#580832)

  - the 'Northbridge Error, node 1, core: -1 K8 ECC error'
    error occurred on some systems using the amd64_edac
    driver. (BZ#580836)

  - in rare circumstances, when using kdump and booting a
    kernel with 'crashkernel=128M@16M', the kdump kernel did
    not boot after a crash. (BZ#580838)

  - TLB page table entry flushing was done incorrectly on
    IBM System z, possibly causing crashes, subtle data
    inconsistency, or other issues. (BZ#580839)

  - iSCSI failover times were slower than in Red Hat
    Enterprise Linux 5.3. (BZ#580840)

  - fixed floating point state corruption after signal.
    (BZ#580841)

  - in certain circumstances, under heavy load, certain
    network interface cards using the bnx2 driver and
    configured to use MSI-X, could stop processing
    interrupts and then network connectivity would cease.
    (BZ#587799)

  - cnic parts resets could cause a deadlock when the bnx2
    device was enslaved in a bonding device and that device
    had an associated VLAN. (BZ#581148)

  - some BIOS implementations initialized interrupt
    remapping hardware in a way the Xen hypervisor
    implementation did not expect. This could have caused a
    system hang during boot. (BZ#581150)

  - AMD Magny-Cours systems panicked when booting a 32-bit
    kernel. (BZ#580846)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1005&L=scientific-linux-errata&T=0&P=1185
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67c378da"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=580199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=580829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=580832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=580836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=580838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=580839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=580840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=580841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=580846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=581148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=581150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=587799"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/06");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-194.3.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-194.3.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-194.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-194.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-194.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-194.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-194.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-194.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-194.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-194.3.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

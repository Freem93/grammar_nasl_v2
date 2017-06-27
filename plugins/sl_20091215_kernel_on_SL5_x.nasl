#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60706);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-3612", "CVE-2009-3620", "CVE-2009-3621", "CVE-2009-3726");

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
"Security fixes :

  - NULL pointer dereference flaws in the r128 driver.
    Checks to test if the Concurrent Command Engine state
    was initialized were missing in private IOCTL functions.
    An attacker could use these flaws to cause a local
    denial of service or escalate their privileges.
    (CVE-2009-3620, Important)

  - a NULL pointer dereference flaw in the NFSv4
    implementation. Several NFSv4 file locking functions
    failed to check whether a file had been opened on the
    server before performing locking operations on it. A
    local user on a system with an NFSv4 share mounted could
    possibly use this flaw to cause a denial of service or
    escalate their privileges. (CVE-2009-3726, Important)

  - a flaw in tcf_fill_node(). A certain data structure in
    this function was not initialized properly before being
    copied to user-space. This could lead to an information
    leak. (CVE-2009-3612, Moderate)

  - unix_stream_connect() did not check if a UNIX domain
    socket was in the shutdown state. This could lead to a
    deadlock. A local, unprivileged user could use this flaw
    to cause a denial of service. (CVE-2009-3621, Moderate)

Bug fixes :

  - frequently changing a CPU between online and offline
    caused a kernel panic on some systems. (BZ#545583)

  - for the LSI Logic LSI53C1030 Ultra320 SCSI controller,
    read commands sent could receive incorrect data,
    preventing correct data transfer. (BZ#529308)

  - pciehp could not detect PCI Express hot plug slots on
    some systems. (BZ#530383)

  - soft lockups: inotify race and contention on
    dcache_lock. (BZ#533822, BZ#537019)

  - priority ordered lists are now used for threads waiting
    for a given mutex. (BZ#533858)

  - a deadlock in DLM could cause GFS2 file systems to lock
    up. (BZ#533859)

  - use-after-free bug in the audit subsystem crashed
    certain systems when running usermod. (BZ#533861)

  - on certain hardware configurations, a kernel panic when
    the Broadcom iSCSI offload driver (bnx2i.ko and cnic.ko)
    was loaded. (BZ#537014)

  - qla2xxx: Enabled MSI-X, and correctly handle the module
    parameter to control it. This improves performance for
    certain systems. (BZ#537020)

  - system crash when reading the cpuaffinity file on a
    system. (BZ#537346)

  - suspend-resume problems on systems with lots of logical
    CPUs, e.g. BX-EX. (BZ#539674)

  - off-by-one error in the legacy PCI bus check.
    (BZ#539675)

  - TSC was not made available on systems with
    multi-clustered APICs. This could cause slow performance
    for time-sensitive applications. (BZ#539676)

  - ACPI: ARB_DISABLE now disabled on platforms that do not
    need it. (BZ#539677)

  - fix node to core and power-aware scheduling issues, and
    a kernel panic during boot on certain AMD Opteron
    processors. (BZ#539678, BZ#540469, BZ#539680, BZ#539682)

  - APIC timer interrupt issues on some AMD Opteron systems
    prevented achieving full power savings. (BZ#539681)

  - general OProfile support for some newer Intel
    processors. (BZ#539683)

  - system crash during boot when NUMA is enabled on systems
    using MC and kernel-xen. (BZ#539684)

  - on some larger systems, performance issues due to a
    spinlock. (BZ#539685)

  - APIC errors when IOMMU is enabled on some AMD Opteron
    systems. (BZ#539687)

  - on some AMD Opteron systems, repeatedly taking a CPU
    offline then online caused a system hang. (BZ#539688)

  - I/O page fault errors on some systems. (BZ#539689)

  - certain memory configurations could cause the kernel-xen
    kernel to fail to boot on some AMD Opteron systems.
    (BZ#539690)

  - NMI watchdog is now disabled for offline CPUs.
    (BZ#539691)

  - duplicate directories in /proc/acpi/processor/ on BX-EX
    systems. (BZ#539692)

  - links did not come up when using bnx2x with certain
    Broadcom devices. (BZ#540381)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0912&L=scientific-linux-errata&T=0&P=2259
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ca07d82"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=529308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=530383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=533822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=533858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=533859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=533861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=537014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=537019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=537020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=537346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=540381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=540469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=545583"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/15");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-164.9.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-164.9.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-164.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-164.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-164.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-164.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-164.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-164.9.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kernel-module-aufs-2.6.18-164.9.1.el5-0.20090202.cvs-6.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kernel-module-aufs-2.6.18-164.9.1.el5xen-0.20090202.cvs-6.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-164.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-164.9.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

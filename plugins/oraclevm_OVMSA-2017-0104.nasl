#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0104.
#

include("compat.inc");

if (description)
{
  script_id(100236);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/17 14:19:07 $");

  script_cve_id("CVE-2016-10229", "CVE-2017-7895");
  script_osvdb_id(154861, 156529, 156530);

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2017-0104)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - ipv6: catch a null skb before using it in a DTRACE
    (Shannon Nelson) 

  - sparc64: Do not retain old VM_SPARC_ADI flag when
    protection changes on page (Khalid Aziz) [Orabug:
    26038830]

  - nfsd: stricter decoding of write-like NFSv2/v3 ops (J.
    Bruce Fields) [Orabug: 25986971] (CVE-2017-7895)

  - sparc64: Detect DAX ra+pgsz when hvapi minor doesn't
    indicate it (Rob Gardner) [Orabug: 25997533]

  - sparc64: DAX memory will use RA+PGSZ feature in HV (Rob
    Gardner) 

  - sparc64: Disable DAX flow control (Rob Gardner) [Orabug:
    25997226]

  - sparc64: DAX memory needs persistent mappings (Rob
    Gardner) [Orabug: 25997137]

  - sparc64: Fix incorrect error print in DAX driver when
    validating ccb (Sanath Kumar) [Orabug: 25996975]

  - sparc64: DAX request for non 4MB memory should return
    with unique errno (Sanath Kumar) [Orabug: 25996823]

  - sparc64: DAX request to mmap non 4MB memory should fail
    with a debug print (Sanath Kumar) [Orabug: 25996823]

  - sparc64: DAX request for non 4MB memory should return
    with unique errno (Sanath Kumar) [Orabug: 25996823]

  - sparc64: Incorrect print by DAX driver when old driver
    API is used (Sanath Kumar) [Orabug: 25996790]

  - sparc64: DAX request to dequeue half of a long CCB
    should not succeed (Sanath Kumar) [Orabug: 25996747]

  - sparc64: dax_overflow_check reports incorrect data
    (Sanath Kumar) 

  - sparc64: Ignored DAX ref count causes lockup (Rob
    Gardner) [Orabug: 25996628]

  - sparc64: disable dax page range checking on RA (Rob
    Gardner) [Orabug: 25996546]

  - sparc64: Oracle Data Analytics Accelerator (DAX) driver
    (Sanath Kumar) [Orabug: 25996522]

  - sparc64: Add DAX hypervisor services (Allen Pais)
    [Orabug: 25996475]

  - sparc64: create/destroy cpu sysfs dynamically (Atish
    Patra) [Orabug: 21775890] [Orabug: 25216469]

  - megaraid: Fix unaligned warning (Allen Pais) [Orabug:
    24817799]

  - Re-enable SDP for uek-nano kernel (Ashok Vairavan)
    [Orabug: 25968572]

  - xsigo: Compute node crash on FC failover (Pradeep
    Gopanapalli) 

  - NVMe: Set affinity after allocating request queues
    (Keith Busch) 

  - nvme: use an integer value to Linux errno values
    (Christoph Hellwig) 

  - blk-mq: fix racy updates of rq->errors (Christoph
    Hellwig) [Orabug: 25945973]

  - x86/apic: Handle zero vector gracefully in
    clear_vector_irq (Keith Busch) [Orabug: 24515998]

  - PCI: Prevent VPD access for QLogic ISP2722 (Ethan Zhao)
    [Orabug: 24819170]

  - PCI: Prevent VPD access for buggy devices (Babu Moger)
    [Orabug: 24819170]

  - ipv6: Skip XFRM lookup if dst_entry in socket cache is
    valid (Jakub Sitnicki) [Orabug: 25525433]

  - Btrfs: don't BUG_ON in btrfs_orphan_add (Josef Bacik)
    [Orabug: 25534945]

  - Btrfs: clarify do_chunk_alloc's return value (Liu Bo)
    [Orabug: 25534945]

  - btrfs: flush_space: treat return value of do_chunk_alloc
    properly (Alex Lyakas) [Orabug: 25534945]

  - Revert '[SCSI] libiscsi: Reduce locking contention in
    fast path' (Ashish Samant) [Orabug: 25721518]

  - qla2xxx: Allow vref count to timeout on vport delete.
    (Joe Carnuccio) [Orabug: 25862953]

  - Drivers: hv: kvp: fix IP Failover (Vitaly Kuznetsov)
    [Orabug: 25866691]

  - Drivers: hv: util: Pass the channel information during
    the init call (K. Y. Srinivasan) [Orabug: 25866691]

  - Drivers: hv: utils: run polling callback always in
    interrupt context (Olaf Hering) [Orabug: 25866691]

  - Drivers: hv: util: Increase the timeout for util
    services (K. Y. Srinivasan) [Orabug: 25866691]

  - Drivers: hv: kvp: check kzalloc return value (Vitaly
    Kuznetsov) 

  - Drivers: hv: fcopy: dynamically allocate smsg_out in
    fcopy_send_data (Vitaly Kuznetsov)

  - Drivers: hv: vss: full handshake support (Vitaly
    Kuznetsov) [Orabug: 25866691]

  - xen: Make VPMU init message look less scary (Juergen
    Gross) [Orabug: 25873416]

  - udp: properly support MSG_PEEK with truncated buffers
    (Eric Dumazet) [Orabug: 25876652] (CVE-2016-10229)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2017-May/000726.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-94.3.4.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-94.3.4.el6uek")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}

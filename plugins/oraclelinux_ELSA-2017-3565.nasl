#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-3565.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(100233);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/17 14:19:06 $");

  script_cve_id("CVE-2016-10229", "CVE-2017-7895");
  script_osvdb_id(156529, 156530);

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2017-3565)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

kernel-uek
[4.1.12-94.3.4.el7uek]
- ipv6: catch a null skb before using it in a DTRACE (Shannon Nelson) 
[Orabug: 26075879]
- sparc64: Do not retain old VM_SPARC_ADI flag when protection changes 
on page (Khalid Aziz)  [Orabug: 26038830]

[4.1.12-94.3.3.el7uek]
- nfsd: stricter decoding of write-like NFSv2/v3 ops (J. Bruce Fields) 
[Orabug: 25986971]  {CVE-2017-7895}

[4.1.12-94.3.2.el7uek]
- sparc64: Detect DAX ra+pgsz when hvapi minor doesn't indicate it (Rob 
Gardner)  [Orabug: 25997533]
- sparc64: DAX memory will use RA+PGSZ feature in HV (Rob Gardner) 
[Orabug: 25997533] [Orabug: 25931417]
- sparc64: Disable DAX flow control (Rob Gardner)  [Orabug: 25997226]
- sparc64: DAX memory needs persistent mappings (Rob Gardner)  [Orabug: 
25997137]
- sparc64: Fix incorrect error print in DAX driver when validating ccb 
(Sanath Kumar)  [Orabug: 25996975]
- sparc64: DAX request for non 4MB memory should return with unique 
errno (Sanath Kumar)  [Orabug: 25996823]
- sparc64: DAX request to mmap non 4MB memory should fail with a debug 
print (Sanath Kumar)  [Orabug: 25996823]
- sparc64: DAX request for non 4MB memory should return with unique 
errno (Sanath Kumar)  [Orabug: 25996823]
- sparc64: Incorrect print by DAX driver when old driver API is used 
(Sanath Kumar)  [Orabug: 25996790]
- sparc64: DAX request to dequeue half of a long CCB should not succeed 
(Sanath Kumar)  [Orabug: 25996747]
- sparc64: dax_overflow_check reports incorrect data (Sanath Kumar) 
[Orabug: 25996655]
- sparc64: Ignored DAX ref count causes lockup (Rob Gardner)  [Orabug: 
25996628]
- sparc64: disable dax page range checking on RA (Rob Gardner)  [Orabug: 
25996546]
- sparc64: Oracle Data Analytics Accelerator (DAX) driver (Sanath Kumar) 
  [Orabug: 25996522]
- sparc64: Add DAX hypervisor services (Allen Pais)  [Orabug: 25996475]
- sparc64: create/destroy cpu sysfs dynamically (Atish Patra)  [Orabug: 
21775890] [Orabug: 25216469]
- megaraid: Fix unaligned warning (Allen Pais)  [Orabug: 24817799]

[4.1.12-94.3.1.el7uek]
- Re-enable SDP for uek-nano kernel (Ashok Vairavan)  [Orabug: 25968572]
- xsigo: Compute node crash on FC failover (Pradeep Gopanapalli) 
[Orabug: 25946533]
- NVMe: Set affinity after allocating request queues (Keith Busch) 
[Orabug: 25945973]
- nvme: use an integer value to Linux errno values (Christoph Hellwig) 
[Orabug: 25945973]
- blk-mq: fix racy updates of rq->errors (Christoph Hellwig)  [Orabug: 
25945973]
- x86/apic: Handle zero vector gracefully in clear_vector_irq() (Keith 
Busch)  [Orabug: 24515998]
- PCI: Prevent VPD access for QLogic ISP2722 (Ethan Zhao)  [Orabug: 
24819170]
- PCI: Prevent VPD access for buggy devices (Babu Moger)  [Orabug: 
24819170]
- ipv6: Skip XFRM lookup if dst_entry in socket cache is valid (Jakub 
Sitnicki)  [Orabug: 25525433]
- Btrfs: don't BUG_ON() in btrfs_orphan_add (Josef Bacik)  [Orabug: 
25534945]
- Btrfs: clarify do_chunk_alloc()'s return value (Liu Bo)  [Orabug: 
25534945]
- btrfs: flush_space: treat return value of do_chunk_alloc properly 
(Alex Lyakas)  [Orabug: 25534945]
- Revert '[SCSI] libiscsi: Reduce locking contention in fast path' 
(Ashish Samant)  [Orabug: 25721518]
- qla2xxx: Allow vref count to timeout on vport delete. (Joe Carnuccio) 
  [Orabug: 25862953]
- Drivers: hv: kvp: fix IP Failover (Vitaly Kuznetsov)  [Orabug: 25866691]
- Drivers: hv: util: Pass the channel information during the init call 
(K. Y. Srinivasan)  [Orabug: 25866691]
- Drivers: hv: utils: run polling callback always in interrupt context 
(Olaf Hering)  [Orabug: 25866691]
- Drivers: hv: util: Increase the timeout for util services (K. Y. 
Srinivasan)  [Orabug: 25866691]
- Drivers: hv: kvp: check kzalloc return value (Vitaly Kuznetsov) 
[Orabug: 25866691]
- Drivers: hv: fcopy: dynamically allocate smsg_out in fcopy_send_data() 
(Vitaly Kuznetsov)
- Drivers: hv: vss: full handshake support (Vitaly Kuznetsov)  [Orabug: 
25866691]
- xen: Make VPMU init message look less scary (Juergen Gross)  [Orabug: 
25873416]
- udp: properly support MSG_PEEK with truncated buffers (Eric Dumazet) 
[Orabug: 25876652]  {CVE-2016-10229}"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-May/006909.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-May/006910.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-4.1.12-94.3.4.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-4.1.12-94.3.4.el7uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"dtrace-modules-4.1.12-94.3.4.el6uek-0.6.0-4.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-4.1.12-94.3.4.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-4.1.12-94.3.4.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.1.12-94.3.4.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-devel-4.1.12-94.3.4.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-doc-4.1.12-94.3.4.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-firmware-4.1.12-94.3.4.el6uek")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"dtrace-modules-4.1.12-94.3.4.el7uek-0.6.0-4.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-4.1.12-94.3.4.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-4.1.12-94.3.4.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.1.12-94.3.4.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-4.1.12-94.3.4.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-4.1.12-94.3.4.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-firmware-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-firmware-4.1.12-94.3.4.el7uek")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}

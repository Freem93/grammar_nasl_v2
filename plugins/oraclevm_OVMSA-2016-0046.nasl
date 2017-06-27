#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0046.
#

include("compat.inc");

if (description)
{
  script_id(90988);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2015-1805", "CVE-2015-8767", "CVE-2016-0774");
  script_bugtraq_id(74951);
  script_osvdb_id(122968, 132811);

  script_name(english:"OracleVM 3.3 : kernel-uek (OVMSA-2016-0046)");
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

  - skbuff: skb_segment: orphan frags before copying (Dongli
    Zhang) 

  - RDS/IB: VRPC DELAY / OSS RECONNECT CAUSES 5 MINUTE STALL
    ON PORT FAILURE (Venkat Venkatsubra) [Orabug: 22888920]

  - mlx4_core: Introduce restrictions for PD update
    (Ajaykumar Hotchandani)

  - filename should be destroyed via final_putname instead
    of __putname (John Sobecki) [Orabug: 22346320]

  - RDS: Fix the atomicity for congestion map update
    (Wengang Wang) 

  - sctp: Prevent soft lockup when sctp_accept is called
    during a timeout event (Karl Heiss) [Orabug: 23222753]
    (CVE-2015-8767)

  - x86_64: expand kernel stack to 16K (Minchan Kim)
    [Orabug: 21140371]

  - iommu/vt-d: add quirk for broken interrupt remapping on
    55XX chipsets (Neil Horman) [Orabug: 22534160]

  - xen: remove unneeded variables and one constant (Daniel
    Kiper) 

  - Revert 'x86/xen: delay construction of mfn_list_list'
    (Daniel Kiper) 

  - ocfs2/dlm: fix misuse of list_move_tail in
    dlm_run_purge_list (Tariq Saeed) [Orabug: 22898384]

  - ocfs2/dlm: do not purge lockres that is queued for
    assert master (Xue jiufei) [Orabug: 22898384]

  - pipe: Fix buffer offset after partially failed read (Ben
    Hutchings) [Orabug: 22985903] (CVE-2016-0774)
    (CVE-2015-1805) (CVE-2016-0774)

  - xen-blkback: replace work_pending with work_busy in
    purge_persistent_gnt (Bob Liu) [Orabug: 22463905]

  - coredump: add new %PATCH variable in core_pattern
    (Herbert van den Bergh) [Orabug: 22666980]

  - veth: don&rsquo t modify ip_summed  doing so treats
    packets with bad checksums as good. (Vijay Pandurangan)
    [Orabug: 22725572]

  - libiscsi: Fix host busy blocking during connection
    teardown (John Soni Jose) [Orabug: 22735756]

  - RDS: Add interface for receive MSG latency trace
    (Santosh Shilimkar) 

  - RDS: Add support for per socket SO_TIMESTAMP for
    incoming messages (Santosh Shilimkar) [Orabug: 22868366]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-May/000457.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-3.8.13-118.6.1.el6uek")) flag++;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-firmware-3.8.13-118.6.1.el6uek")) flag++;

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

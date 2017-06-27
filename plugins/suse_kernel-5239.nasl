#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59127);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/05/17 14:34:35 $");

  script_cve_id("CVE-2008-2136");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 5239)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

  - tunneled ipv6 packets (SIT) could trigger a memory leak
    in the kernel. Remote attackers could exploit that to
    crash machines. (CVE-2008-2136)

Additionally the following bugfixes have been included for all
platforms :

  - patches.xfs/xfs-kern_31033a_Fix-fsync-b0rkage.patch: Fix
    XFS fsync breakage. (bnc#388798)

  - patches.fixes/sit-add-missing-kfree_skb: sit - Add
    missing kfree_skb() on pskb_may_pull() failure. .
    (bnc#389152)

  -
    patches.xfs/xfs-kern_30701a_Ensure-a-btree-insert-return
    s-a- valid-cursor.patch: Ensure a btree insert returns a
    valid cursor. ( bnc#388806).

  - patches.fixes/369802_d_path_fix.patch: fix d_path for
    pseudo filesystems. (bnc#369802)

  - patches.fixes/ignore_lost_ticks: fixed
    do_vgettimeofday() and other issues with this patch.
    (bnc#267050)

  - patches.drivers/pci-express-aer-aerdriver-off.patch: PCI

  - add possibility to turn AER off. (bnc#382033)

  - patches.drivers/pci-express-aer-documentation: PCI - add
    AER documentation. (bnc#382033)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2136.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5239.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.23")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.23")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.23")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.23")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.23")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.23")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.23")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.23")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.23")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.23")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.23")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");

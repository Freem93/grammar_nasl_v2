#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59146);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/22 20:42:26 $");

  script_cve_id("CVE-2009-3556", "CVE-2009-4020", "CVE-2010-0410");

  script_name(english:"SuSE 10 Security Update : Linux kernel (x86_64) (ZYPP Patch Number 6929)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes lots of bugs and some security issues in the SUSE
Linux Enterprise 10 SP 3 kernel.

  - A stack-based buffer overflow in the HFS subsystem of
    the Linux kernel allows remote attackers to have an
    unspecified impact via a crafted Hierarchical File
    System (HFS) filesystem, related to the hfs_readdir()
    function in fs/hfs/dir.c. CVE-2010-0410: The connector
    netlink driver (drivers/connector/connector.c) of the
    Linux kernel allows local users to cause a denial of
    service (memory consumption or system crash) by sending
    the kernel many NETLINK_CONNECTOR messages.
    CVE-2009-3556: A configuration value in the qla2xxx
    driver of the Linux kernel when N_Port ID Virtualization
    (NPIV) hardware is used, sets world-writable permissions
    for the vport_create and vport_delete files under
    /sys/class/scsi_host/, which allows local users to make
    arbitrary changes to SCSI host attributes by modifying
    these files. (CVE-2009-4020)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3556.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0410.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6929.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(119, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.60.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.60.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.60.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.60.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.60.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.60.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.60.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.60.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.60.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.60.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.60.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.60.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");

#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41535);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/22 20:32:47 $");

  script_cve_id("CVE-2007-6716", "CVE-2008-1514", "CVE-2008-3525", "CVE-2008-3528", "CVE-2008-4210");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 5668)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update for SUSE Linux Enterprise 10 Service Pack 2 fixes
various bugs and some security problems :

  - When creating a file, open()/creat() allowed the setgid
    bit to be set via the mode argument even when, due to
    the bsdgroups mount option or the file being created in
    a setgid directory, the new file's group is one which
    the user is not a member of. The local attacker could
    then use ftruncate() and memory-mapped I/O to turn the
    new file into an arbitrary binary and thus gain the
    privileges of this group, since these operations do not
    clear the setgid bit.'. (CVE-2008-4210)

  - The ext[234] filesystem code fails to properly handle
    corrupted data structures. With a mounted filesystem
    image or partition that have corrupted dir->i_size and
    dir->i_blocks, a user performing either a read or write
    operation on the mounted image or partition can lead to
    a possible denial of service by spamming the logfile.
    (CVE-2008-3528)

  - The S/390 ptrace code allowed local users to cause a
    denial of service (kernel panic) via the
    user-area-padding test from the ptrace testsuite in
    31-bit mode, which triggers an invalid dereference.
    (CVE-2008-1514)

  - fs/direct-io.c in the dio subsystem in the Linux kernel
    did not properly zero out the dio struct, which allows
    local users to cause a denial of service (OOPS), as
    demonstrated by a certain fio test. (CVE-2007-6716)

  - Added missing capability checks in sbni_ioctl().
    (CVE-2008-3525)

Also OCFS2 was updated to version v1.4.1-1.

The full amount of changes can be reviewed in the RPM changelog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6716.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1514.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3525.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3528.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-4210.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5668.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.31")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-default-2.6.16.60-0.31")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.31")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-source-2.6.16.60-0.31")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.31")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.31")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.31")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.31")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-debug-2.6.16.60-0.31")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-default-2.6.16.60-0.31")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-kdump-2.6.16.60-0.31")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.31")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-source-2.6.16.60-0.31")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.31")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-vmi-2.6.16.60-0.31")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-vmipae-2.6.16.60-0.31")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.31")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.31")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");

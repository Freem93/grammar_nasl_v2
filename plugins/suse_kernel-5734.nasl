#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35026);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2012/10/03 00:00:33 $");

  script_cve_id("CVE-2007-6716", "CVE-2008-3528", "CVE-2008-4210");

  script_name(english:"SuSE 10 Security Update : Linux Kernel (x86) (ZYPP Patch Number 5734)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This patch updates the SUSE Linux Enterprise 10 SP1 kernel. It fixes
various bugs and security issues.

The following security issues are addressed :

  - fs/open.c in the Linux kernel before 2.6.22 does not
    properly strip setuid and setgid bits when there is a
    write to a file, which allows local users to gain the
    privileges of a different group, and obtain sensitive
    information or possibly have unspecified other impact,
    by creating an executable file in a setgid directory
    through the (1) truncate or (2) ftruncate function in
    conjunction with memory-mapped I/O. (CVE-2008-4210)

  - The ext[234] filesystem code fails to properly handle
    corrupted data structures. With a mounted filesystem
    image or partition that have corrupted dir->i_size and
    dir->i_blocks, a user performing either a read or write
    operation on the mounted image or partition can lead to
    a possible denial of service by spamming the logfile.
    (CVE-2008-3528)

  - fs/direct-io.c in the dio subsystem in the Linux kernel
    did not properly zero out the dio struct, which allows
    local users to cause a denial of service (OOPS), as
    demonstrated by a certain fio test. (CVE-2007-6716)

All other bugfixes can be found by looking at the RPM changelog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6716.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3528.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-4210.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5734.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-bigsmp-2.6.16.54-0.2.12")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-default-2.6.16.54-0.2.12")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-smp-2.6.16.54-0.2.12")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-source-2.6.16.54-0.2.12")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-syms-2.6.16.54-0.2.12")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-xen-2.6.16.54-0.2.12")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-xenpae-2.6.16.54-0.2.12")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-bigsmp-2.6.16.54-0.2.12")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-debug-2.6.16.54-0.2.12")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-default-2.6.16.54-0.2.12")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-kdump-2.6.16.54-0.2.12")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-smp-2.6.16.54-0.2.12")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-source-2.6.16.54-0.2.12")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-syms-2.6.16.54-0.2.12")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-xen-2.6.16.54-0.2.12")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-xenpae-2.6.16.54-0.2.12")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");

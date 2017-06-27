#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42465);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/22 20:32:47 $");

  script_cve_id("CVE-2009-1192", "CVE-2009-1633", "CVE-2009-2848", "CVE-2009-2909", "CVE-2009-2910", "CVE-2009-3002", "CVE-2009-3238", "CVE-2009-3547");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 6632)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a several security issues and various bugs in the
SUSE Linux Enterprise 10 SP 2 kernel.

The following security issues were fixed: CVE-2009-3547: A race
condition during pipe open could be used by local attackers to elevate
privileges.

  - On x86_64 systems a information leak of high register
    contents (upper 32bit) was fixed. (CVE-2009-2910)

  - The randomness of the ASLR methods used in the kernel
    was increased. (CVE-2009-3238)

  - A information leak from the kernel due to uninitialized
    memory in AGP handling was fixed. (CVE-2009-1192)

  - A signed comparison in the ax25 sockopt handler was
    fixed which could be used to crash the kernel or
    potentially execute code. (CVE-2009-2909)

  - The execve function in the Linux kernel did not properly
    clear the current->clear_child_tid pointer, which allows
    local users to cause a denial of service (memory
    corruption) or possibly gain privileges via a clone
    system call with CLONE_CHILD_SETTID or
    CLONE_CHILD_CLEARTID enabled, which is not properly
    handled during thread creation and exit. (CVE-2009-2848)

  - Fixed various sockethandler getname leaks, which could
    disclose memory previously used by the kernel or other
    userland processes to the local attacker.
    (CVE-2009-3002)

  - Multiple buffer overflows in the cifs subsystem in the
    Linux kernel allow remote CIFS servers to cause a denial
    of service (memory corruption) and possibly have
    unspecified other impact via (1) a malformed Unicode
    string, related to Unicode string area alignment in
    fs/cifs/sess.c; or (2) long Unicode characters, related
    to fs/cifs/cifssmb.c and the cifs_readdir function in
    fs/cifs/readdir.c. (CVE-2009-1633)

Also see the RPM changelog for more changes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1192.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1633.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2848.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2909.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2910.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3238.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3547.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6632.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 189, 200, 310, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/11");
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
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.42.7")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-default-2.6.16.60-0.42.7")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.42.7")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-source-2.6.16.60-0.42.7")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.42.7")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.42.7")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.42.7")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.42.7")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-debug-2.6.16.60-0.42.7")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-default-2.6.16.60-0.42.7")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-kdump-2.6.16.60-0.42.7")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.42.7")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-source-2.6.16.60-0.42.7")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.42.7")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-vmi-2.6.16.60-0.42.7")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-vmipae-2.6.16.60-0.42.7")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.42.7")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.42.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");

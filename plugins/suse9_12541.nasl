#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42812);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/21 20:33:29 $");

  script_cve_id("CVE-2009-1192", "CVE-2009-1633", "CVE-2009-2848", "CVE-2009-2909", "CVE-2009-2910", "CVE-2009-3002", "CVE-2009-3547", "CVE-2009-3726");

  script_name(english:"SuSE9 Security Update : Linux kernel (YOU Patch Number 12541)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes various security issues and some bugs in the SUSE
Linux Enterprise 9 kernel.

The following security bugs were fixed :

  - A race condition in the pipe(2) systemcall could be used
    by local attackers to execute code. (CVE-2009-3547)

  - On x86_64 systems a information leak of high register
    contents (upper 32bit) was fixed. (CVE-2009-2910)

  - The (1) agp_generic_alloc_page and (2)
    agp_generic_alloc_pages functions in
    drivers/char/agp/generic.c in the agp subsystem in the
    Linux kernel do not zero out pages that may later be
    available to a user-space process, which allows local
    users to obtain sensitive information by reading these
    pages. (CVE-2009-1192)

  - Unsigned check in the ax25 socket handler could allow
    local attackers to potentially crash the kernel or even
    execute code. (CVE-2009-2909)

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

  - The nfs4_proc_lock function in fs/nfs/nfs4proc.c in the
    NFSv4 client in the allows remote NFS servers to cause a
    denial of service (NULL pointer dereference and panic)
    by sending a certain response containing incorrect file
    attributes, which trigger attempted use of an open file
    that lacks NFSv4 state. (CVE-2009-3726)"
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
    value:"http://support.novell.com/security/cve/CVE-2009-3547.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3726.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12541.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 189, 200, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/16");
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
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-bigsmp-2.6.5-7.321")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-debug-2.6.5-7.321")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-default-2.6.5-7.321")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-smp-2.6.5-7.321")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-source-2.6.5-7.321")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-syms-2.6.5-7.321")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-um-2.6.5-7.321")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-xen-2.6.5-7.321")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-xenpae-2.6.5-7.321")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"um-host-install-initrd-1.0-48.34")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"um-host-kernel-2.6.5-7.321")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"xen-kmp-3.0.4_2.6.5_7.321-0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");

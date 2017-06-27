#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59137);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/22 20:32:47 $");

  script_cve_id("CVE-2009-0834", "CVE-2009-0835", "CVE-2009-0859", "CVE-2009-1072", "CVE-2009-1265", "CVE-2009-1337", "CVE-2009-1439");

  script_name(english:"SuSE 10 Security Update : the Linux kernel (ZYPP Patch Number 6236)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Linux kernel on SUSE Linux Enterprise 10 Service Pack 2 was
updated to fix various security issues and several bugs.

The following security issues were fixed: CVE-2009-0834: The
audit_syscall_entry function in the Linux kernel on the x86_64
platform did not properly handle (1) a 32-bit process making a 64-bit
syscall or (2) a 64-bit process making a 32-bit syscall, which allows
local users to bypass certain syscall audit configurations via crafted
syscalls.

  - nfsd in the Linux kernel did not drop the CAP_MKNOD
    capability before handling a user request in a thread,
    which allows local users to create device nodes, as
    demonstrated on a filesystem that has been exported with
    the root_squash option. (CVE-2009-1072)

  - The __secure_computing function in kernel/seccomp.c in
    the seccomp subsystem in the Linux kernel on the x86_64
    platform, when CONFIG_SECCOMP is enabled, does not
    properly handle (1) a 32-bit process making a 64-bit
    syscall or (2) a 64-bit process making a 32-bit syscall,
    which allows local users to bypass intended access
    restrictions via crafted syscalls that are
    misinterpreted as (a) stat or (b) chmod. (CVE-2009-0835)

  - Buffer overflow in fs/cifs/connect.c in CIFS in the
    Linux kernel 2.6.29 and earlier allows remote attackers
    to cause a denial of service (crash) or potential code
    execution via a long nativeFileSystem field in a Tree
    Connect response to an SMB mount request.
    (CVE-2009-1439)

This requires that kernel can be made to mount a 'cifs' filesystem
from a malicious CIFS server.

  - The exit_notify function in kernel/exit.c in the Linux
    kernel did not restrict exit signals when the CAP_KILL
    capability is held, which allows local users to send an
    arbitrary signal to a process by running a program that
    modifies the exit_signal field and then uses an exec
    system call to launch a setuid application.
    (CVE-2009-1337)

  - The shm_get_stat function in ipc/shm.c in the shm
    subsystem in the Linux kernel, when CONFIG_SHMEM is
    disabled, misinterprets the data type of an inode, which
    allows local users to cause a denial of service (system
    hang) via an SHM_INFO shmctl call, as demonstrated by
    running the ipcs program. (SUSE is enabling
    CONFIG_SHMEM, so is by default not affected, the fix is
    just for completeness). (CVE-2009-0859)

The GCC option -fwrapv has been added to compilation to work around
potentially removing integer overflow checks.

  - Integer overflow in rose_sendmsg (sys/net/af_rose.c) in
    the Linux kernel might allow attackers to obtain
    sensitive information via a large length value, which
    causes 'garbage' memory to be sent. (CVE-2009-1265)

Also a number of bugs were fixed, for details please see the RPM
changelog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0834.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0859.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1072.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1265.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1337.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1439.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6236.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(16, 20, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/12");
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
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.39.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.39.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.39.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.39.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.39.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.39.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.39.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.39.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.39.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.39.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.39.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.39.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");

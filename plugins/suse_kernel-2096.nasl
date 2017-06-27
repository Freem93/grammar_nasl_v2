#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59121);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/05/17 14:34:35 $");

  script_cve_id("CVE-2006-3468", "CVE-2006-3745", "CVE-2006-4093");

  script_name(english:"SuSE 10 Security Update : Linux kernel (x86_64) (ZYPP Patch Number 2096)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

  - A double userspace copy in a SCTP ioctl allows local
    attackers to overflow a buffer in the kernel,
    potentially allowing code execution and privilege
    escalation. [#199441]. (CVE-2006-3745)

  - Local attackers were able to crash PowerPC systems with
    PPC970 processor using a not correctly disabled
    privileged instruction ('attn'). [#197810].
    (CVE-2006-4093)

  - Remote attackers able to access an NFS of a ext2 or ext3
    filesystem can cause a denial of service (file system
    panic) via a crafted UDP packet with a V2 lookup
    procedure that specifies a bad file handle (inode
    number), which triggers an error and causes an exported
    directory to be remounted read-only. [#192988].
    (CVE-2006-3468)

and the following non security bugs :

  - XEN patches/fixes :

  - kunmap_atomic() must zap the PTE to avoid dangling
    references.

  - Fix oops on io scheduler unload on a process without ioc
    (backport)

  - OCFS2 updated to to version 1.2.3.

  - update patches.arch/ppc-update_gtod-race.patch: restrict
    to 64bit only because it leads to deadlocks on ppc32
    [#202146]

  - Fix MCA recovery in context switch path [#199472]

  - fix gettimeofday vs. update_gtod race [#197699]

  - LKCD: dump all slab pages. [#196330]

  - Make idle io be lowest priority best-effort [#195387]

  - Fix dropping of wrong cic. [#195387]

  - Fix stale file handle problem with subtree_checking.
    [#195040]

  - Remove Altix PROM bit that can race on MCAs. [#193296]

  - Prevent silent data corruption caused by XPC. [#193132]

  - Fix race condition during COW [#192259]

  - sched: fix group power for allnodes_domains [#191929]

  - Allow dma_alloc_coherent() to work for regions up to
    2MB. [#191615]

  - fix ABBA deadlock between cpuset callback_sem and
    hotplug cpucontrol mutex [#191582]

  - Check for existing sysfs directory prior to creating one
    [#191360]

  - Fix possible NFS panic in readdir. [#189951]

  - MPT driver: Fix oops on module loading [#189534]

  - SUNRPC: Ensure that rpc_mkpipe returns a refcounted
    dentry [#183013]

  - Pass file mode on DMAPI remove events [#182691]

  - MPT driver: Fix oops during error recovery [#177919]

  - flush icache on POWER4 cpus to fix itrace crash
    [#171699]

  - KPROBES: Fix system panic if user doing copy_from_user
    in the probe handlers [#171483]

  - patches.xen/xen-balloon-max-target: Expose limit domain
    can be ballooned up to [#152667]

  - Avoid possible soft-lockup, particularly related to md
    [#152099]

  - reiserfs: fix transaction overflowing [#145070]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3468.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3745.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-4093.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 2096.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/19");
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
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"kernel-default-2.6.16.21-0.25")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"kernel-smp-2.6.16.21-0.25")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"kernel-source-2.6.16.21-0.25")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"kernel-syms-2.6.16.21-0.25")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-debug-2.6.16.21-0.25")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-default-2.6.16.21-0.25")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-smp-2.6.16.21-0.25")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-source-2.6.16.21-0.25")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-syms-2.6.16.21-0.25")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-xen-2.6.16.21-0.25")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");

#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(51158);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/01/14 15:30:09 $");

  script_cve_id("CVE-2010-2226", "CVE-2010-2248", "CVE-2010-2942", "CVE-2010-2946", "CVE-2010-3067", "CVE-2010-3086", "CVE-2010-3310", "CVE-2010-3437", "CVE-2010-3442", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4078", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4158", "CVE-2010-4162", "CVE-2010-4164");

  script_name(english:"SuSE 10 Security Update : the Linux kernel (ZYPP Patch Number 7257)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update for the SUSE Linux Enterprise 10 SP3 kernel fixes
several security issues and bugs.

The following security issues were fixed :

  - Multiple integer overflows in the snd_ctl_new function
    in sound/core/control.c in the Linux kernel before
    2.6.36-rc5-next-20100929 allow local users to cause a
    denial of service (heap memory corruption) or possibly
    have unspecified other impact via a crafted (1)
    SNDRV_CTL_IOCTL_ELEM_ADD or (2)
    SNDRV_CTL_IOCTL_ELEM_REPLACE ioctl call. (CVE-2010-3442)

  - Integer signedness error in the pkt_find_dev_from_minor
    function in drivers/block/pktcdvd.c in the Linux kernel
    before 2.6.36-rc6 allows local users to obtain sensitive
    information from kernel memory or cause a denial of
    service (invalid pointer dereference and system crash)
    via a crafted index value in a PKT_CTRL_CMD_STATUS ioctl
    call. (CVE-2010-3437)

  - Uninitialized stack memory disclosure in the
    FBIOGET_VBLANK ioctl in the sis and ivtv drivers could
    leak kernel memory to userspace. (CVE-2010-4078)

  - Uninitialized stack memory disclosure in the rme9652
    ALSA driver could leak kernel memory to userspace.
    (CVE-2010-4080 / CVE-2010-4081)

  - Uninitialized stack memory disclosure in the SystemV IPC
    handling functions could leak kernel memory to
    userspace. (CVE-2010-4073 / CVE-2010-4072 /
    CVE-2010-4083)

  - Integer overflow in the do_io_submit function in
    fs/aio.c in the Linux kernel allowed local users to
    cause a denial of service or possibly have unspecified
    other impact via crafted use of the io_submit system
    call. (CVE-2010-3067)

  - Multiple integer signedness errors in net/rose/af_rose.c
    in the Linux kernel allowed local users to cause a
    denial of service (heap memory corruption) or possibly
    have unspecified other impact via a rose_getname
    function call, related to the rose_bind and rose_connect
    functions. (CVE-2010-3310)

  - The xfs_swapext function in fs/xfs/xfs_dfrag.c in the
    Linux kernel did not properly check the file descriptors
    passed to the SWAPEXT ioctl, which allowed local users
    to leverage write access and obtain read access by
    swapping one file into another file. (CVE-2010-2226)

  - fs/jfs/xattr.c in the Linux kernel did not properly
    handle a certain legacy format for storage of extended
    attributes, which might have allowed local users by
    bypass intended xattr namespace restrictions via an
    'os2.' substring at the beginning of a name.
    (CVE-2010-2946)

  - The actions implementation in the network queueing
    functionality in the Linux kernel did not properly
    initialize certain structure members when performing
    dump operations, which allowed local users to obtain
    potentially sensitive information from kernel memory via
    vectors related to (1) the tcf_gact_dump function in
    net/sched/act_gact.c, (2) the tcf_mirred_dump function
    in net/sched/act_mirred.c, (3) the tcf_nat_dump function
    in net/sched/act_nat.c, (4) the tcf_simp_dump function
    in net/sched/act_simple.c, and (5) the tcf_skbedit_dump
    function in net/sched/act_skbedit.c. (CVE-2010-2942)

  - fs/cifs/cifssmb.c in the CIFS implementation in the
    Linux kernel allowed remote attackers to cause a denial
    of service (panic) via an SMB response packet with an
    invalid CountHigh value, as demonstrated by a response
    from an OS/2 server, related to the CIFSSMBWrite and
    CIFSSMBWrite2 functions. (CVE-2010-2248)

  - A 32bit vs 64bit integer mismatch in gdth_ioctl_alloc
    could lead to memory corruption in the GDTH driver.
    (CVE-2010-4157)

  - A remote (or local) attacker communicating over X.25
    could cause a kernel panic by attempting to negotiate
    malformed facilities. (CVE-2010-4164)

  - A missing lock prefix in the x86 futex code could be
    used by local attackers to cause a denial of service.
    (CVE-2010-3086)

  - A memory information leak in berkely packet filter rules
    allowed local attackers to read uninitialized memory of
    the kernel stack. (CVE-2010-4158)

  - A local denial of service in the blockdevice layer was
    fixed. (CVE-2010-4162)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2226.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2248.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2942.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2946.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3067.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3086.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3310.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3437.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3442.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4072.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4073.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4078.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4081.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4157.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4158.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4162.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4164.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7257.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-default-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-source-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-debug-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-default-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-kdump-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-kdumppae-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-source-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-vmi-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-vmipae-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.74.7")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.74.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");

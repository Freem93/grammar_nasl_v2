#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66782);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/04 10:58:40 $");

  script_cve_id("CVE-2012-4444", "CVE-2013-1928");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 8587)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 10 SP4 kernel has been updated to fix
various bugs and security issues.

Security issues fixed :

  - The ip6_frag_queue function in net/ipv6/reassembly.c in
    the Linux kernel allowed remote attackers to bypass
    intended network restrictions via overlapping IPv6
    fragments. (CVE-2012-4444)

  - The do_video_set_spu_palette function in
    fs/compat_ioctl.c in the Linux kernel lacked a certain
    error check, which might have allowed local users to
    obtain sensitive information from kernel stack memory
    via a crafted VIDEO_SET_SPU_PALETTE ioctl call on a
    /dev/dvb device. (CVE-2013-1928)

Also the following bugs have been fixed :

  - hugetlb: Fix regression introduced by the original
    patch. (bnc#790236, bnc#819403)

  - NFSv3/v2: Fix data corruption with NFS short reads.
    (bnc#818337)

  - Fix package descriptions in specfiles. (bnc#817666)

  - TTY: fix atime/mtime regression. (bnc#815745)

  - virtio_net: ensure big packets are 64k. (bnc#760753)

  - virtio_net: refill rx buffers when oom occurs.
    (bnc#760753)

  - qeth: fix qeth_wait_for_threads() deadlock for OSN
    devices (bnc#812317, LTC#90910).

  - nfsd: remove unnecessary NULL checks from
    nfsd_cross_mnt. (bnc#810628)

  - knfsd: Fixed problem with NFS exporting directories
    which are mounted on. (bnc#810628)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4444.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1928.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8587.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.103.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");

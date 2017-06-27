#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:0856-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83586);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2012-4444", "CVE-2013-1928");
  script_bugtraq_id(56891, 58906);

  script_name(english:"SUSE SLED10 / SLES10 Security Update : kernel (SUSE-SU-2013:0856-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 10 SP4 kernel has been updated to fix
various bugs and security issues.

Security issues fixed :

CVE-2012-4444: The ip6_frag_queue function in net/ipv6/reassembly.c in
the Linux kernel allowed remote attackers to bypass intended network
restrictions via overlapping IPv6 fragments.

CVE-2013-1928: The do_video_set_spu_palette function in
fs/compat_ioctl.c in the Linux kernel lacked a certain error
check, which might have allowed local users to obtain
sensitive information from kernel stack memory via a crafted
VIDEO_SET_SPU_PALETTE ioctl call on a /dev/dvb device.

Also the following bugs have been fixed :

  - hugetlb: Fix regression introduced by the original patch
    (bnc#790236, bnc#819403).

  - NFSv3/v2: Fix data corruption with NFS short reads
    (bnc#818337).

  - Fix package descriptions in specfiles (bnc#817666).

  - TTY: fix atime/mtime regression (bnc#815745).

  - virtio_net: ensure big packets are 64k (bnc#760753).

  - virtio_net: refill rx buffers when oom occurs
    (bnc#760753).

  - qeth: fix qeth_wait_for_threads() deadlock for OSN
    devices (bnc#812317, LTC#90910).

  - nfsd: remove unnecessary NULL checks from nfsd_cross_mnt
    (bnc#810628).

  - knfsd: Fixed problem with NFS exporting directories
    which are mounted on (bnc#810628).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=42590e04eddb51fa31379710deb16611
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?076f03bf"
  );
  # http://download.suse.com/patch/finder/?keywords=4f3691ec5a62d5e0a58b289de36e7ba5
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3349e6ff"
  );
  # http://download.suse.com/patch/finder/?keywords=60a0921c1bb3961c00333f60f45fee0b
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7706f28"
  );
  # http://download.suse.com/patch/finder/?keywords=806641e6eb093ae891357f0c47c7e76f
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db84cd39"
  );
  # http://download.suse.com/patch/finder/?keywords=b108e81194a14724506e0d40a5303d13
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5333171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4444.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1928.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/760753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/789831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/790236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/810628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/812317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/813735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/815745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/817666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/818337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/819403"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20130856-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12ad4baa"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kdumppae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vmipae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED10|SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED10 / SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLED10 SP4", os_ver + " SP" + sp);
if (os_ver == "SLES10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"kernel-bigsmp-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"kernel-xenpae-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"kernel-default-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"kernel-smp-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"kernel-source-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"kernel-syms-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"kernel-xen-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-bigsmp-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-kdumppae-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-vmi-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-vmipae-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-xenpae-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"kernel-default-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"kernel-source-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"kernel-syms-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-debug-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-kdump-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-smp-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-xen-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-kdumppae-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-vmi-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-vmipae-2.6.16.60-0.103.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.103.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(51609);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/03/14 14:55:46 $");

  script_cve_id("CVE-2010-1641", "CVE-2010-2066", "CVE-2010-2495");

  script_name(english:"SuSE 11.1 Security Update : Linux Kernel (SAT Patch Numbers 2760 / 2763 / 2764)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This SUSE Linux Enterprise 11 Service Pack 1 kernel contains various
security fixes and other bugfixes.

Notable larger bug fixes and changes :

  - A deadlock in virtual interface handling in XEN
    introduced by the last update has been fixed.

  - The btrfs file system received backports of lots of
    fixes from 2.6.35.

  - An OCFS2 data corruption during high load has been
    fixed.

  - Custom truncation length has been added for
    authentication mechanisms in XFRM to enable IPv6
    certification. The following security issues have been
    fixed :

  - Several buffer overflows in the Novell Client novfs
    kernel module could be abused by local users to execute
    code in kernel space.

  - On ext4 file systems, the MOVE_EXT ioctl() can overwrite
    append-only files. (CVE-2010-2066)

  - A NULL pointer de-reference in the l2tp protocol can
    cause an oops, which leads to a denial of service.
    (CVE-2010-2495)

  - Insufficient permission checking for the setflags
    ioctl() in the gfs2 filesystem. (CVE-2010-1641)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=501563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=557710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=574006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=594362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=596113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=598308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=599671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=603528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=606575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=607123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=608435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=608576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=609506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=610362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=611104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=612457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=613171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=613542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=614793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=615003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=616088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=616369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=616612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=617248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=618767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=619007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=619416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=619536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=619840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=620020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=620021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=620904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=623472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1641.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2066.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2495.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 2760 / 2763 / 2764 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:btrfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:btrfs-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:btrfs-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:hyper-v-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:hyper-v-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"btrfs-kmp-default-0_2.6.32.13_0.5-0.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"btrfs-kmp-pae-0_2.6.32.13_0.5-0.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"btrfs-kmp-xen-0_2.6.32.13_0.5-0.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"hyper-v-kmp-default-0_2.6.32.13_0.5-0.7.7")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"hyper-v-kmp-pae-0_2.6.32.13_0.5-0.7.7")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-base-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-devel-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-extra-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-desktop-devel-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-base-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-devel-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-extra-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-source-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-syms-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-base-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-devel-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-extra-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"btrfs-kmp-default-0_2.6.32.13_0.5-0.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"btrfs-kmp-xen-0_2.6.32.13_0.5-0.3.9")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"hyper-v-kmp-default-0_2.6.32.13_0.5-0.7.7")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-base-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-devel-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-extra-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-desktop-devel-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-source-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-syms-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-base-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-devel-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-extra-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"btrfs-kmp-default-0_2.6.32.13_0.5-0.3.9")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"ext4dev-kmp-default-0_2.6.32.13_0.5-7.3.9")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-default-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-default-base-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-default-devel-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-source-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-syms-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-trace-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-trace-base-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-trace-devel-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"btrfs-kmp-pae-0_2.6.32.13_0.5-0.3.9")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"btrfs-kmp-xen-0_2.6.32.13_0.5-0.3.9")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"ext4dev-kmp-pae-0_2.6.32.13_0.5-7.3.9")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"ext4dev-kmp-xen-0_2.6.32.13_0.5-7.3.9")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"hyper-v-kmp-default-0_2.6.32.13_0.5-0.7.7")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"hyper-v-kmp-pae-0_2.6.32.13_0.5-0.7.7")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-pae-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-pae-base-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-pae-devel-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-xen-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-xen-base-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-xen-devel-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"kernel-default-man-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"btrfs-kmp-xen-0_2.6.32.13_0.5-0.3.9")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"ext4dev-kmp-xen-0_2.6.32.13_0.5-7.3.9")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"hyper-v-kmp-default-0_2.6.32.13_0.5-0.7.7")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-xen-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-xen-base-2.6.32.13-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-xen-devel-2.6.32.13-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

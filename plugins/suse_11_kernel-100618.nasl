#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51608);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/25 23:46:55 $");

  script_cve_id("CVE-2010-1173");

  script_name(english:"SuSE 11.1 Security Update : Linux kernel (SAT Patch Numbers 2568 / 2569 / 2570)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This SUSE Linux Enterprise 11 Service Pack 1 kernel update brings the
Linux kernel to version 2.6.32.13. It also contains a fix for the
following security issue :

  - If SCTP is enabled, the sctp_process_unk_param function
    in net/sctp/sm_make_chunk.c allows remote attackers to
    cause a denial of service (system crash) via an
    SCTPChunkInit packet containing multiple invalid
    parameters that require a large amount of error data.
    (CVE-2010-1173)

Additionally, the update fixes various minor bugs as documented in the
kernel RPM package changelog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=468397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=578572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=580373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=585385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=588929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=598493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=598677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=599508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=600256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=600375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=602232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=603387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=603411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=603510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=605001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=605321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=605947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=606743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=606778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=606797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=607448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=607628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=607890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=608435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=608478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=609281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=610362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=610598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=610783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=611760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=613906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1173.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 2568 / 2569 / 2570 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"btrfs-kmp-default-0_2.6.32.13_0.4-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"btrfs-kmp-pae-0_2.6.32.13_0.4-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"btrfs-kmp-xen-0_2.6.32.13_0.4-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"hyper-v-kmp-default-0_2.6.32.13_0.4-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"hyper-v-kmp-pae-0_2.6.32.13_0.4-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-base-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-devel-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-extra-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-desktop-devel-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-base-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-devel-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-extra-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-source-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-syms-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-base-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-devel-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-extra-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"btrfs-kmp-default-0_2.6.32.13_0.4-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"btrfs-kmp-xen-0_2.6.32.13_0.4-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"hyper-v-kmp-default-0_2.6.32.13_0.4-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-base-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-devel-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-extra-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-desktop-devel-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-source-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-syms-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-base-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-devel-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-extra-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"btrfs-kmp-default-0_2.6.32.13_0.4-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"ext4dev-kmp-default-0_2.6.32.13_0.4-7.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-default-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-default-base-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-default-devel-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-source-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-syms-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-trace-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-trace-base-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-trace-devel-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"btrfs-kmp-pae-0_2.6.32.13_0.4-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"btrfs-kmp-xen-0_2.6.32.13_0.4-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"ext4dev-kmp-pae-0_2.6.32.13_0.4-7.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"ext4dev-kmp-xen-0_2.6.32.13_0.4-7.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"hyper-v-kmp-default-0_2.6.32.13_0.4-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"hyper-v-kmp-pae-0_2.6.32.13_0.4-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-pae-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-pae-base-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-pae-devel-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-xen-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-xen-base-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-xen-devel-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"kernel-default-man-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"btrfs-kmp-xen-0_2.6.32.13_0.4-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"ext4dev-kmp-xen-0_2.6.32.13_0.4-7.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"hyper-v-kmp-default-0_2.6.32.13_0.4-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-xen-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-xen-base-2.6.32.13-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-xen-devel-2.6.32.13-0.4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

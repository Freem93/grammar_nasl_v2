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
  script_id(41410);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2009-0676", "CVE-2009-0835", "CVE-2009-1072");

  script_name(english:"SuSE 11 Security Update : Linux kernel (SAT Patch Numbers 713 / 715 / 716)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Linux kernel update for SUSE Linux Enterprise 11 fixes lots of
bugs and some security issues.

The kernel was also updated to the 2.6.27.21 stable release.

  - nfsd in the Linux kernel does not drop the CAP_MKNOD
    capability before handling a user request in a thread,
    which allows local users to create device nodes, as
    demonstrated on a filesystem that has been exported with
    the root_squash option. (CVE-2009-1072)

  - The sock_getsockopt function in net/core/sock.c in the
    Linux kernel does not initialize a certain structure
    member, which allows local users to obtain potentially
    sensitive information from kernel memory via an
    SO_BSDCOMPAT getsockopt request. The fix for this was
    incomplete. (CVE-2009-0676)

  - The __secure_computing function in kernel/seccomp.c in
    the seccomp subsystem in the Linux kernel on the x86_64
    platform, when CONFIG_SECCOMP is enabled, does not
    properly handle (1) a 32-bit process making a 64-bit
    syscall or (2) a 64-bit process making a 32-bit syscall,
    which allows local users to bypass intended access
    restrictions via crafted syscalls that are
    misinterpreted as (a) stat or (b) chmod. (CVE-2009-0835)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=417417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=439348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=441420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=450468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=457472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=458222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=462913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=463829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=465854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=465955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=467174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=467317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=467381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=469576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=470238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=471249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=472783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=473881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=474335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=476330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=477624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=478534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=479558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=479617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=479730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=479784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=480391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=480448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=480524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=480617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=480749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=480753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=480809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=481749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=482052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=482220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=482506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=482614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=482796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=482818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=483706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=484529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=484664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=484767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=485089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=486001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=486331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=486728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=487247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=490517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0676.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1072.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 713 / 715 / 716 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_cwe_id(16, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-vmi-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-default-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-default-base-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-default-extra-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-pae-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-pae-base-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-pae-extra-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-source-2.6.27.21-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-syms-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-xen-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-xen-base-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-xen-extra-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-default-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-default-base-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-default-extra-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-source-2.6.27.21-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-syms-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-xen-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-xen-base-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-xen-extra-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"ext4dev-kmp-default-0_2.6.27.21_0.1-7.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kernel-default-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kernel-default-base-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kernel-source-2.6.27.21-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kernel-syms-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"ext4dev-kmp-pae-0_2.6.27.21_0.1-7.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"ext4dev-kmp-vmi-0_2.6.27.21_0.1-7.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"ext4dev-kmp-xen-0_2.6.27.21_0.1-7.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-pae-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-pae-base-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-vmi-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-vmi-base-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-xen-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-xen-base-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"kernel-default-man-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"ext4dev-kmp-xen-0_2.6.27.21_0.1-7.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"kernel-xen-2.6.27.21-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"kernel-xen-base-2.6.27.21-0.1.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

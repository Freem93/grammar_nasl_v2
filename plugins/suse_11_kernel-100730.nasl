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
  script_id(50923);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/25 23:46:55 $");

  script_name(english:"SuSE 11 Security Update : Linux kernel (SAT Patch Numbers 2838 / 2841 / 2842)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Kernel was updated fixing a single
regression :

The previous update contained an erronous fix which broke the IPv4 GRE
tunneling module. This regression is fixed by this update.

No other change is contained in this update, if you are not using the
module, this update is not required."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=580799"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 2838 / 2841 / 2842 as appropriate."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-default-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-default-base-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-default-extra-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-pae-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-pae-base-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-pae-extra-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-source-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-syms-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-xen-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-xen-base-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-xen-extra-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-default-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-default-base-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-default-extra-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-source-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-syms-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-xen-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-xen-base-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-xen-extra-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"ext4dev-kmp-default-0_2.6.27.48_0.6-7.1.36")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kernel-default-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kernel-default-base-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kernel-source-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kernel-syms-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"ext4dev-kmp-pae-0_2.6.27.48_0.6-7.1.36")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"ext4dev-kmp-vmi-0_2.6.27.48_0.6-7.1.36")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"ext4dev-kmp-xen-0_2.6.27.48_0.6-7.1.36")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-pae-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-pae-base-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-vmi-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-vmi-base-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-xen-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-xen-base-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"kernel-default-man-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"ext4dev-kmp-xen-0_2.6.27.48_0.6-7.1.36")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"kernel-xen-2.6.27.48-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"kernel-xen-base-2.6.27.48-0.6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

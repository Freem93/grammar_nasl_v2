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
  script_id(71763);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/12/28 16:06:01 $");

  script_name(english:"SuSE 11.2 / 11.3 Security Update : acroread (SAT Patch Numbers 8688 / 8689)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Adobe has discontinued the support of Adobe Reader for Linux in June
2013.

Newer security problems and bugs are no longer fixed.

As the Adobe Reader is binary only software and we cannot provide a
replacement, SUSE declares the acroread package of Adobe Reader as
being out of support and unmaintained.

If you do not need Acrobat Reader, we recommend to uninstall the
'acroread' package.

This update removes the Acrobat Reader PDF plugin to avoid automatic
exploitation by clicking on web pages with embedded PDFs.

The stand alone 'acroread' binary is still available, but again, we do
not recommend to use it."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843835"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8688 / 8689 as appropriate."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-cmaps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-fonts-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-fonts-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-fonts-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-fonts-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread_ja");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"acroread-9.5.5-0.5.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"acroread-cmaps-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"acroread-fonts-ja-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"acroread-fonts-ko-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"acroread-fonts-zh_CN-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"acroread-fonts-zh_TW-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"acroread_ja-9.4.2-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"acroread-cmaps-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"acroread-fonts-ja-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"acroread-fonts-ko-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"acroread-fonts-zh_CN-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"acroread-fonts-zh_TW-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"acroread-9.5.5-0.5.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"acroread-cmaps-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"acroread-fonts-ja-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"acroread-fonts-ko-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"acroread-fonts-zh_CN-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"acroread-fonts-zh_TW-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"acroread-cmaps-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"acroread-fonts-ja-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"acroread-fonts-ko-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"acroread-fonts-zh_CN-9.4.6-0.4.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"acroread-fonts-zh_TW-9.4.6-0.4.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

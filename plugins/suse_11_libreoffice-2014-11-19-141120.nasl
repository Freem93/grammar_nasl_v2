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
  script_id(79687);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/03 11:50:43 $");

  script_cve_id("CVE-2014-3693");

  script_name(english:"SuSE 11.3 Security Update : LibreOffice (SAT Patch Number 10001)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"LibreOffice was updated to fix two security issues.

These security issues have been fixed :

  - 'Document as E-mail' vulnerability. (bnc#900218)

  - Impress remote control use-after-free vulnerability.
    (CVE-2014-3693)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=900214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=900218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3693.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10001.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-base-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-draw-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-en-US");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-zh-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-zh-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-icon-themes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-impress-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-zh-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-zh-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-base-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-base-drivers-postgresql-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-base-extensions-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-calc-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-calc-extensions-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-draw-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-draw-extensions-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-filters-optional-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-gnome-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-cs-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-da-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-de-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-en-GB-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-en-US-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-es-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-fr-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-gu-IN-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-hi-IN-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-hu-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-it-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-ja-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-ko-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-nl-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-pl-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-pt-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-pt-BR-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-ru-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-sv-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-zh-CN-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-zh-TW-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-icon-themes-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-impress-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-impress-extensions-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-kde-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-kde4-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-af-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-ar-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-ca-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-cs-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-da-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-de-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-en-GB-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-es-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-fi-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-fr-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-gu-IN-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-hi-IN-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-hu-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-it-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-ja-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-ko-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-nb-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-nl-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-nn-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-pl-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-pt-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-pt-BR-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-ru-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-sk-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-sv-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-xh-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-zh-CN-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-zh-TW-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-zu-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-mailmerge-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-math-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-mono-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-officebean-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-pyuno-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-writer-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-writer-extensions-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-base-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-base-extensions-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-calc-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-calc-extensions-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-draw-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-draw-extensions-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-filters-optional-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-gnome-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-cs-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-da-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-de-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-en-GB-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-en-US-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-es-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-fr-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-gu-IN-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-hi-IN-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-hu-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-it-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-ja-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-ko-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-nl-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-pl-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-pt-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-pt-BR-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-ru-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-sv-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-zh-CN-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-zh-TW-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-icon-themes-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-impress-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-impress-extensions-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-kde-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-kde4-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-af-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-ar-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-ca-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-cs-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-da-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-de-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-en-GB-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-es-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-fi-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-fr-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-gu-IN-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-hi-IN-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-hu-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-it-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-ja-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-ko-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-nb-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-nl-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-nn-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-pl-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-pt-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-pt-BR-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-ru-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-sk-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-sv-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-xh-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-zh-CN-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-zh-TW-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-zu-4.0.3.3.26-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-mailmerge-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-math-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-mono-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-officebean-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-pyuno-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-writer-4.0.3.3.26-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-writer-extensions-4.0.3.3.26-0.10.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

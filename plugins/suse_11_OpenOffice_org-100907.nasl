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
  script_id(50878);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/10/25 23:52:02 $");

  script_cve_id("CVE-2010-2935", "CVE-2010-2936");

  script_name(english:"SuSE 11 / 11.1 Security Update : OpenOffice_org (SAT Patch Numbers 3087 / 3089)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted ppt files could cause a heap-based buffer overflow
in OpenOffice_org Impress. Attackers could exploit that to crash
OpenOffice_org or potentially even execute arbitrary code.
(CVE-2010-2935 / CVE-2010-2936)

This update also fixes numerous non-security bugs. Please refer to the
package changelog for details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=527738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=607735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=612902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=615000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=617593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=618846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=618864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=620924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=621116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=622920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=623352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=623944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=628098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=629085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=629546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=631993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=634974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2935.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2936.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 3087 / 3089 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-base-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-components");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-draw-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-en-US");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-en-US-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-zh-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-help-zh-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-icon-themes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-impress-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-zh-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-zh-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-libs-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-libs-extern");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-libs-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:OpenOffice_org-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/07");
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


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-base-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-base-drivers-postgresql-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-base-extensions-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-calc-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-calc-extensions-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-components-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-draw-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-draw-extensions-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-filters-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-filters-optional-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-gnome-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-ar-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-cs-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-da-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-de-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-en-GB-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-en-US-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-en-US-devel-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-es-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-fr-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-gu-IN-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-hi-IN-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-hu-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-it-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-ja-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-ko-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-nl-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-pl-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-pt-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-pt-BR-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-ru-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-sv-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-zh-CN-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-help-zh-TW-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-icon-themes-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-impress-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-impress-extensions-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-kde-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-af-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-ar-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-ca-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-cs-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-da-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-de-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-el-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-en-GB-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-es-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-extras-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-fi-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-fr-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-gu-IN-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-hi-IN-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-hu-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-it-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-ja-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-ko-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-nb-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-nl-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-nn-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-pl-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-pt-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-pt-BR-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-ru-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-sk-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-sv-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-xh-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-zh-CN-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-zh-TW-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-l10n-zu-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-libs-core-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-libs-extern-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-libs-gui-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-mailmerge-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-math-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-mono-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-officebean-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-pyuno-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-ure-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-writer-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"OpenOffice_org-writer-extensions-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-base-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-base-drivers-postgresql-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-base-extensions-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-calc-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-calc-extensions-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-components-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-draw-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-draw-extensions-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-filters-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-filters-optional-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-gnome-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-ar-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-cs-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-da-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-de-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-en-GB-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-en-US-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-en-US-devel-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-es-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-fr-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-gu-IN-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-hi-IN-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-hu-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-it-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-ja-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-ko-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-nl-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-pl-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-pt-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-pt-BR-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-ru-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-sv-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-zh-CN-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-help-zh-TW-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-icon-themes-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-impress-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-impress-extensions-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-kde-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-af-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-ar-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-ca-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-cs-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-da-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-de-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-el-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-en-GB-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-es-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-extras-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-fi-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-fr-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-gu-IN-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-hi-IN-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-hu-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-it-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-ja-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-ko-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-nb-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-nl-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-nn-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-pl-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-pt-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-pt-BR-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-ru-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-sk-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-sv-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-xh-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-zh-CN-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-zh-TW-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-l10n-zu-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-libs-core-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-libs-extern-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-libs-gui-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-mailmerge-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-math-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-mono-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-officebean-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-pyuno-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-ure-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-writer-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"OpenOffice_org-writer-extensions-3.2.1.6-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-base-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-base-drivers-postgresql-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-base-extensions-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-calc-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-calc-extensions-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-components-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-draw-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-draw-extensions-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-filters-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-filters-optional-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-gnome-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-ar-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-cs-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-da-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-de-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-en-GB-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-en-US-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-es-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-fr-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-gu-IN-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-hi-IN-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-hu-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-it-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-ja-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-ko-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-nl-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-pl-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-pt-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-pt-BR-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-ru-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-sv-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-zh-CN-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-help-zh-TW-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-icon-themes-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-impress-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-impress-extensions-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-kde-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-af-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-ar-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-ca-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-cs-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-da-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-de-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-en-GB-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-es-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-extras-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-fi-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-fr-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-gu-IN-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-hi-IN-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-hu-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-it-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-ja-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-ko-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-nb-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-nl-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-nn-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-pl-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-pt-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-pt-BR-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-ru-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-sk-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-sv-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-xh-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-zh-CN-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-zh-TW-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-l10n-zu-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-libs-core-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-libs-extern-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-libs-gui-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-mailmerge-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-math-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-mono-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-officebean-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-pyuno-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-ure-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-writer-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"OpenOffice_org-writer-extensions-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-base-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-base-drivers-postgresql-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-base-extensions-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-calc-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-calc-extensions-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-components-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-draw-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-draw-extensions-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-filters-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-filters-optional-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-gnome-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-ar-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-cs-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-da-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-de-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-en-GB-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-en-US-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-es-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-fr-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-gu-IN-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-hi-IN-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-hu-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-it-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-ja-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-ko-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-nl-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-pl-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-pt-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-pt-BR-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-ru-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-sv-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-zh-CN-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-help-zh-TW-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-icon-themes-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-impress-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-impress-extensions-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-kde-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-af-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-ar-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-ca-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-cs-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-da-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-de-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-en-GB-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-es-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-extras-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-fi-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-fr-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-gu-IN-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-hi-IN-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-hu-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-it-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-ja-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-ko-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-nb-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-nl-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-nn-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-pl-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-pt-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-pt-BR-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-ru-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-sk-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-sv-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-xh-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-zh-CN-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-zh-TW-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-l10n-zu-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-libs-core-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-libs-extern-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-libs-gui-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-mailmerge-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-math-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-mono-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-officebean-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-pyuno-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-ure-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-writer-3.2.1.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"OpenOffice_org-writer-extensions-3.2.1.6-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

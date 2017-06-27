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
  script_id(81909);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/18 15:21:15 $");

  script_cve_id("CVE-2013-7252");

  script_name(english:"SuSE 11.3 Security Update : kdebase4-runtime (SAT Patch Number 10404)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"kdebase4-runtime has been updated to fix one security issue :

  - Added gpg based encryption support to kwallet.
    (bnc#857200). (CVE-2013-7252)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=857200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7252.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10404.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-csb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-da-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-da-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-de-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-de-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-es-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-es-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-fr-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-fr-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-it-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-it-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-ku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-nds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-nl-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-nl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-pl-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-pl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-pt_BR-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-pt_BR-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-ru-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-ru-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-sv-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-sv-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-wa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-l10n-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kdebase4-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kdebase4-runtime-xine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/18");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-ar-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-cs-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-da-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-da-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-da-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-de-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-de-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-de-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-en_GB-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-es-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-es-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-es-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-fr-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-fr-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-fr-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-hu-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-it-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-it-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-it-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-ja-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-ko-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-nb-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-nl-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-nl-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-nl-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-pl-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-pl-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-pl-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-pt-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-pt_BR-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-pt_BR-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-pt_BR-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-ru-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-ru-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-ru-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-sv-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-sv-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-sv-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-zh_CN-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-l10n-zh_TW-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kdebase4-runtime-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kdebase4-runtime-xine-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-ar-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-cs-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-da-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-da-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-da-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-de-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-de-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-de-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-en_GB-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-es-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-es-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-es-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-fr-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-fr-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-fr-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-hu-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-it-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-it-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-it-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-ja-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-ko-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-nb-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-nl-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-nl-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-nl-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-pl-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-pl-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-pl-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-pt-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-pt_BR-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-pt_BR-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-pt_BR-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-ru-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-ru-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-ru-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-sv-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-sv-data-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-sv-doc-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-zh_CN-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-l10n-zh_TW-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kdebase4-runtime-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kdebase4-runtime-xine-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-ar-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-bg-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-ca-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-cs-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-csb-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-da-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-de-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-el-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-en_GB-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-es-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-et-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-eu-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-fi-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-fr-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-ga-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-gl-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-hi-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-hu-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-is-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-it-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-ja-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-kk-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-km-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-ko-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-ku-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-lt-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-lv-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-mk-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-ml-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-nb-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-nds-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-nl-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-nn-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-pa-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-pl-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-pt-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-pt_BR-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-ro-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-ru-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-sl-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-sv-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-th-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-tr-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-uk-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-wa-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-zh_CN-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-l10n-zh_TW-4.3.5-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kdebase4-runtime-4.3.5-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

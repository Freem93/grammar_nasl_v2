#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-700.
#

include("compat.inc");

if (description)
{
  script_id(26082);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 22:04:03 $");

  script_cve_id("CVE-2007-2834");
  script_xref(name:"FEDORA", value:"2007-700");

  script_name(english:"Fedora Core 6 : openoffice.org-2.0.4-5.5.24 (2007-700)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security updates addresses CVE-2007-2834 a flaw in how
openoffice.org handles corrupt TIFF graphic format file headers

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-September/003838.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?abaae23d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-javafilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-af_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-as_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-bg_BG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-ca_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-cs_CZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-cy_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-da_DK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-el_GR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-et_EE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-eu_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-fi_FI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-ga_IE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-gl_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-he_IL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-hi_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-hr_HR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-ja_JP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-kn_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-ko_KR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-lt_LT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-ml_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-mr_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-ms_MY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-nr_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-nso_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-or_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-pa_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-pl_PL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-sk_SK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-sl_SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-sr_CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-ss_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-st_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-ta_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-te_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-th_TH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-tn_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-tr_TR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-ts_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-ve_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-xh_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-langpack-zu_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-testtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 6.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC6", reference:"openoffice.org-base-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-calc-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-core-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-debuginfo-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-draw-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-emailmerge-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-graphicfilter-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-impress-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-javafilter-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-af_ZA-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-ar-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-as_IN-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-bg_BG-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-bn-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-ca_ES-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-cs_CZ-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-cy_GB-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-da_DK-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-de-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-el_GR-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-es-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-et_EE-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-eu_ES-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-fi_FI-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-fr-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-ga_IE-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-gl_ES-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-gu_IN-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-he_IL-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-hi_IN-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-hr_HR-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-hu_HU-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-it-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-ja_JP-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-kn_IN-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-ko_KR-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-lt_LT-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-ml_IN-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-mr_IN-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-ms_MY-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-nb_NO-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-nl-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-nn_NO-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-nr_ZA-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-nso_ZA-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-or_IN-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-pa_IN-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-pl_PL-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-pt_BR-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-pt_PT-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-ru-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-sk_SK-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-sl_SI-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-sr_CS-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-ss_ZA-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-st_ZA-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-sv-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-ta_IN-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-te_IN-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-th_TH-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-tn_ZA-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-tr_TR-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-ts_ZA-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-ur-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-ve_ZA-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-xh_ZA-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-zh_CN-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-zh_TW-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-langpack-zu_ZA-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-math-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-pyuno-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-testtools-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-writer-2.0.4-5.5.24")) flag++;
if (rpm_check(release:"FC6", reference:"openoffice.org-xsltfilter-2.0.4-5.5.24")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openoffice.org-base / openoffice.org-calc / openoffice.org-core / etc");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:126. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(37988);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_cve_id(
    "CVE-2007-1362",
    "CVE-2007-2867",
    "CVE-2007-2868",
    "CVE-2007-2869",
    "CVE-2007-2870",
    "CVE-2007-2871"
  );
  script_bugtraq_id(24242);
  script_osvdb_id(
    35134,
    35135,
    35136,
    35137,
    35138,
    35139,
    35140
  );
  script_xref(name:"MDKSA", value:"2007:126-1");

  script_name(english:"Mandrake Linux Security Advisory : mozilla-firefox (MDKSA-2007:126-1)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A number of security vulnerabilities have been discovered and
corrected in the latest Mozilla Firefox program, version 2.0.0.4.

This update provides the latest Firefox to correct these issues.

Update :

The l10n language packages have now been updated and are available."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-14.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-17.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:deskbar-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:devhelp-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:eclipse-ecj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:eclipse-jdt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:eclipse-jdt-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:eclipse-pde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:eclipse-pde-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:eclipse-pde-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:eclipse-platform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:eclipse-platform-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:eclipse-rcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:eclipse-rcp-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:eclipse-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:epiphany-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:epiphany-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gda-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gksu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gtkhtml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gtkmozembed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnome-python-gtkspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64devhelp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64devhelp-1_0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mozilla-firefox2.0.0.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mozilla-firefox2.0.0.4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64totem-plparser1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64totem-plparser1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libdevhelp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libdevhelp-1_0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmozilla-firefox2.0.0.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmozilla-firefox2.0.0.4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libswt3-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtotem-plparser1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtotem-plparser1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-br_FR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-es_AR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-es_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-sv_SE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-uk_UA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:totem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:totem-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:totem-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:totem-mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:totem-mozilla-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2007.1", reference:"deskbar-applet-2.18.0-3.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"devhelp-0.13-3.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"devhelp-plugins-0.13-3.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"eclipse-ecj-3.2.2-3.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"eclipse-jdt-3.2.2-3.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"eclipse-jdt-sdk-3.2.2-3.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"eclipse-pde-3.2.2-3.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"eclipse-pde-runtime-3.2.2-3.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"eclipse-pde-sdk-3.2.2-3.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"eclipse-platform-3.2.2-3.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"eclipse-platform-sdk-3.2.2-3.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"eclipse-rcp-3.2.2-3.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"eclipse-rcp-sdk-3.2.2-3.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"eclipse-sdk-3.2.2-3.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"epiphany-2.18.0-5.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"epiphany-devel-2.18.0-5.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"epiphany-extensions-2.18.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"galeon-2.0.3-5.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"gnome-python-extras-2.14.3-4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"gnome-python-gda-2.14.3-4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"gnome-python-gda-devel-2.14.3-4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"gnome-python-gdl-2.14.3-4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"gnome-python-gksu-2.14.3-4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"gnome-python-gtkhtml2-2.14.3-4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"gnome-python-gtkmozembed-2.14.3-4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"gnome-python-gtkspell-2.14.3-4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64devhelp-1_0-0.13-3.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64devhelp-1_0-devel-0.13-3.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64mozilla-firefox2.0.0.4-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64mozilla-firefox2.0.0.4-devel-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64totem-plparser1-2.18.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64totem-plparser1-devel-2.18.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libdevhelp-1_0-0.13-3.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libdevhelp-1_0-devel-0.13-3.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libmozilla-firefox2.0.0.4-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libmozilla-firefox2.0.0.4-devel-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"libswt3-gtk2-3.2.2-3.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libtotem-plparser1-2.18.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libtotem-plparser1-devel-2.18.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-ar-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-bg-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-br_FR-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-ca-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-cs-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-da-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-de-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-el-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-es_AR-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-es_ES-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-eu-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-fi-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-fr-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-fy-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-ga-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-gu_IN-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-hu-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-it-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-ja-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-ko-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-lt-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-mk-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-nb_NO-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-nl-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-nn_NO-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-pl-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-pt_BR-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-pt_PT-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-ru-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-sk-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-sl-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-sv_SE-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-tr-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-uk_UA-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-zh_CN-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mozilla-firefox-zh_TW-2.0.0.4-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"totem-2.18.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"totem-common-2.18.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"totem-gstreamer-2.18.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"totem-mozilla-2.18.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"totem-mozilla-gstreamer-2.18.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"yelp-2.18.0-3.1mdv2007.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

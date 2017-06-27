#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:143. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(23892);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_cve_id("CVE-2006-2613", "CVE-2006-2775", "CVE-2006-2776", "CVE-2006-2777", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-2782", "CVE-2006-2783", "CVE-2006-2784", "CVE-2006-2785", "CVE-2006-2786", "CVE-2006-2787", "CVE-2006-2788", "CVE-2006-2894", "CVE-2006-2900", "CVE-2006-3113", "CVE-2006-3677", "CVE-2006-3801", "CVE-2006-3802", "CVE-2006-3803", "CVE-2006-3804", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810", "CVE-2006-3811", "CVE-2006-3812", "CVE-2007-1794");
  script_bugtraq_id(18308);
  script_xref(name:"MDKSA", value:"2006:143-1");

  script_name(english:"Mandrake Linux Security Advisory : mozilla-firefox (MDKSA-2006:143-1)");
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
corrected in the latest Mozilla Firefox program.

Previous updates to Firefox were patch fixes to Firefox 1.0.6 that
brought it in sync with 1.0.8 in terms of security fixes. In this
update, Mozilla Firefox 1.5.0.6 is being provided which corrects a
number of vulnerabilities that were previously unpatched, as well as
providing new and enhanced features.

The following CVE names have been corrected with this update:
CVE-2006-2613, CVE-2006-2894, CVE-2006-2775, CVE-2006-2776,
CVE-2006-2777, CVE-2006-2778, CVE-2006-2779, CVE-2006-2780,
CVE-2006-2782, CVE-2006-2783, CVE-2006-2784, CVE-2006-2785,
CVE-2006-2786, CVE-2006-2787, CVE-2006-2788, CVE-2006-3677,
CVE-2006-3803, CVE-2006-3804, CVE-2006-3806, CVE-2006-3807,
CVE-2006-3113, CVE-2006-3801, CVE-2006-3802, CVE-2006-3805,
CVE-2006-3808, CVE-2006-3809, CVE-2006-3810, CVE-2006-3811,
CVE-2006-3812.

Update :

The previous language packages were not correctly tagged for the new
Firefox which resulted in many of them not loading properly. These
updated language packages correct the problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-31.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-32.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-33.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-34.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-35.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-36.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-37.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-38.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-39.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-41.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-42.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-43.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-44.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-45.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-46.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-47.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-48.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-50.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-51.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-52.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-53.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-54.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-55.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-56.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox Navigator Object Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 94, 119, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-firefox-zh_TW");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-br-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-ca-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-cs-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-da-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-de-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-el-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-es-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-fi-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-fr-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-ga-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-he-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-hu-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-it-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-ja-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-ko-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-nb-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-nl-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-pl-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-pt_BR-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-ro-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-ru-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-sk-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-sl-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-sv-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-tr-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-zh_CN-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-firefox-zh_TW-1.5.0.6-0.2.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

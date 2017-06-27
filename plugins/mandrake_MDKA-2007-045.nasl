# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2012/09/06.
#

#
# (C) Tenable Network Security, Inc.
#
# This script was automatically generated from
# Mandrake Linux Security Advisory MDKA-2007:045.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(37520);
  script_version ("$Revision: 1.7 $"); 
  script_cvs_date("$Date: 2012/09/07 00:24:00 $");

  script_name(english:"MDKA-2007:045 : mozilla-thunderbird");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Mandriva Linux 2007.1 shipped with a beta version of Mozilla
Thunderbird, so this update provides the final Mozilla Thunderbird
2.0.0.0 release, with updated translations and Enigmail support.

This update also adds support for Belarusian (be), Bulgarian (bg),
Danish (da), British English (en-GB), Irish (ga-IE), Lithuanian (lt),
Macedonian (mk), Norwegian Nynorsk (nn-NO), Portuguese Portugal
(pt-PT), and Traditional Chinese (zh-TW).

Finally, the language support for cs, nl, pt, sk, sl, and es_AR are
currently disabled for Enigmail due to lack of upstream updates.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKA-2007:045");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/22");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/23");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");


include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Mandrake/release")) exit(0, "The host is not running Mandrake Linux.");
if (!get_kb_item("Host/Mandrake/rpm-list")) exit(1, "Could not get the list of packages.");

flag = 0;

if (rpm_check(reference:"mozilla-thunderbird-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-be-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-bg-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ca-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-cs-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-da-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-de-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-devel-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-el-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-en_GB-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-ca-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-de-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-el-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-es-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-fi-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-fr-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-hu-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-it-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-ja-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-nb-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-pl-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-pt_BR-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-ru-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-sv-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-zh_CN-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-es-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-es_AR-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-eu-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-fi-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-fr-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-gu_IN-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-he-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-hu-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-it-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ja-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ko-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-lt-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-mk-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-nb-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-nl-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-nn_NO-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-pa_IN-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-pl-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-pt_BR-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-pt_PT-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ru-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-sk-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-sl-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-sv-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-tr-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-zh_CN-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-zh_TW-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nsinstall-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"mozilla-thunderbird-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-be-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-bg-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ca-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-cs-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-da-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-de-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-devel-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-el-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-en_GB-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-ca-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-de-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-el-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-es-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-fi-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-fr-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-hu-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-it-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-ja-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-nb-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-pl-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-pt_BR-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-ru-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-sv-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-zh_CN-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-es-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-es_AR-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-eu-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-fi-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-fr-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-gu_IN-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-he-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-hu-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-it-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ja-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ko-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-lt-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-mk-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-nb-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-nl-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-nn_NO-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-pa_IN-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-pl-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-pt_BR-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-pt_PT-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ru-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-sk-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-sl-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-sv-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-tr-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-zh_CN-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-zh_TW-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nsinstall-2.0.0.0-1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else 
{
  exit(0, "The host is not affected.");
}

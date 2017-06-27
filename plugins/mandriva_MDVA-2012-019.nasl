#%NASL_MIN_LEVEL 99999
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
# Mandriva Linux Security Advisory MDVA-2012:019.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(57927);
  script_version("$Revision: 1.3 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:11 $");

  script_name(english:"MDVA-2012:019 : mozilla-thunderbird");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"This is a maintenance and bugfix release that provides thunderbird
10.0.1 which utilizes better compilation optimizarions.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2012:019");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/13");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/14");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

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

if (rpm_check(reference:"mozilla-thunderbird-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-lightning-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nsinstall-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"mozilla-thunderbird-ar-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-be-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-bg-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-bn_BD-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-br-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ca-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-cs-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-da-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-de-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-el-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-en_GB-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-ar-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-ca-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-cs-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-de-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-el-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-es-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-fi-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-fr-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-it-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-ja-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-ko-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-nb-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-nl-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-pl-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-pt-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-pt_BR-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-ru-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-sl-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-sv-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-tr-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-vi-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-zh_CN-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-zh_TW-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-es_AR-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-es_ES-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-et-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-eu-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-fi-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-fr-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-fy-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ga-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-gd-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-gl-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-he-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-hu-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-id-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-is-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-it-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ja-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ko-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-lt-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-nb_NO-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-nl-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-nn_NO-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-pl-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-pt_BR-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-pt_PT-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ro-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ru-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-si-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-sk-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-sl-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-sq-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-sv_SE-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ta_LK-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-tr-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-uk-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-vi-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-zh_CN-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-zh_TW-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ar-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-be-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-bg-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-bn_BD-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-br-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ca-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-cs-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-da-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-de-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-el-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-en_GB-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-ar-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-ca-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-cs-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-de-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-el-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-es-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-fi-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-fr-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-it-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-ja-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-ko-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-nb-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-nl-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-pl-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-pt-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-pt_BR-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-ru-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-sl-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-sv-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-tr-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-vi-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-zh_CN-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-zh_TW-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-es_AR-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-es_ES-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-et-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-eu-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-fi-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-fr-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-fy-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ga-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-gd-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-gl-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-he-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-hu-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-id-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-is-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-it-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ja-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ko-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-lt-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-nb_NO-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-nl-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-nn_NO-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-pl-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-pt_BR-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-pt_PT-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ro-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ru-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-si-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-sk-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-sl-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-sq-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-sv_SE-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-ta_LK-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-tr-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-uk-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-vi-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-zh_CN-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-zh_TW-10.0.1-0.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;

if (rpm_check(reference:"mozilla-thunderbird-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-enigmail-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mozilla-thunderbird-lightning-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nsinstall-10.0.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;


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

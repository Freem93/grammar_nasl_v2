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
# Mandriva Linux Security Advisory MDVA-2012:007.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(57832);
  script_version("$Revision: 1.3 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:11 $");

  script_name(english:"MDVA-2012:007 : firefox");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"This is a maintenance and bugfix release for firefox 10.0 which
utilizes better compilation optimizarions. Additionally a few more
language packs has been added.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2012:007");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/05");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/06");
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

if (rpm_check(reference:"firefox-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-devel-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"firefox-af-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ar-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ast-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-be-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-bg-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-bn_BD-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-bn_IN-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-br-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-bs-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ca-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-cs-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-cy-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-da-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-de-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-el-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-en_GB-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-en_ZA-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-eo-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-es_AR-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-es_CL-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-es_ES-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-es_MX-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-et-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-eu-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-fa-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-fi-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-fr-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-fy-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ga_IE-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-gd-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-gl-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-gu_IN-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-he-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-hi-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-hr-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-hu-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-hy-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-id-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-is-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-it-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ja-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-kk-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-kn-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ko-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ku-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-lg-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-lt-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-lv-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-mai-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-mk-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ml-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-mr-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-nb_NO-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-nl-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-nn_NO-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-nso-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-or-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-pa_IN-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-pl-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-pt_BR-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-pt_PT-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ro-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ru-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-si-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-sk-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-sl-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-sq-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-sr-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-sv_SE-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ta-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ta_LK-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-te-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-th-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-tr-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-uk-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-vi-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-zh_CN-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-zh_TW-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-zu-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-af-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ar-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ast-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-be-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-bg-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-bn_BD-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-bn_IN-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-br-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-bs-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ca-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-cs-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-cy-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-da-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-de-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-el-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-en_GB-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-en_ZA-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-eo-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-es_AR-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-es_CL-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-es_ES-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-es_MX-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-et-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-eu-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-fa-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-fi-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-fr-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-fy-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ga_IE-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-gd-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-gl-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-gu_IN-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-he-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-hi-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-hr-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-hu-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-hy-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-id-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-is-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-it-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ja-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-kk-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-kn-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ko-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ku-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-lg-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-lt-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-lv-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-mai-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-mk-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ml-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-mr-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-nb_NO-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-nl-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-nn_NO-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-nso-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-or-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-pa_IN-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-pl-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-pt_BR-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-pt_PT-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ro-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ru-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-si-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-sk-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-sl-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-sq-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-sr-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-sv_SE-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ta-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-ta_LK-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-te-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-th-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-tr-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-uk-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-vi-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-zh_CN-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-zh_TW-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-zu-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;

if (rpm_check(reference:"firefox-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"firefox-devel-10.0-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;


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

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
# Mandriva Linux Security Advisory MDVA-2008:107.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(37671);
  script_version ("$Revision: 1.8 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:05 $");

  script_name(english:"MDVA-2008:107 : myspell-dictionaries");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Some thesaurus files of some languages were not properly working witn
Mandriva Linux 2008.1. The thesaurus would not bring out the meaning
and synonym for any searched word for the following languages:
American English, Spanish, French, German, Polish, Czeck, Slovakian,
and Hungarian. This release updates the thesaurus files for these
languages so that they will work with the Mandriva OpenOffice.org
version 2.4.1.5.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2008:107");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/15");
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

if (rpm_check(reference:"myspell-af_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-am_AM-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ar_AR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-az_AZ-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-bg_BG-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-bn_BN-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ca_ES-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-cop_EG-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-csb_CSB-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-cs_CZ-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-cy_GB-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-da_DK-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-de_AT-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-de_CH-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-de_DE-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-el_GR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-en_AU-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-en_CA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-en_GB-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-en_NZ-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-en_US-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-en_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-eo_EO-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-es_ES-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-es_MX-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-et_EE-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-eu_ES-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fa_FA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fa_IR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fi_FI-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fj_FJ-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fo_FO-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fr_BE-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fr_FR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fur_IT-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fy_NL-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ga_IE-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-gd_GB-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-gl_ES-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-gsc_FR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-he_IL-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-hi_IN-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-hr_HR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-hu_HU-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-hy_AM-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-id_ID-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-is_IS-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-it_IT-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-km_KH-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ku_TR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-la_LA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-lt_LT-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-lv_LV-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-mg_MG-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-mi_NZ-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-mn_MN-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-mr_IN-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ms_MY-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-nb_NO-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ne_NP-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-nl_NL-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-nn_NO-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-nr_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ns_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ny_MW-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-oc_FR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-or_OR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-pa_PA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-pl_PL-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-pt_BR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-pt_PT-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-qu_BO-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ro_RO-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ru_RU-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-rw_RW-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-sk_SK-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-sl_SI-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ss_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-st_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-sv_SE-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-sw_KE-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-sw_TZ-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ta_TA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-tet_ID-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-th_TH-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-tl_PH-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-tn_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ts_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-uk_UA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-uz_UZ-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ve_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-vi_VI-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-xh_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-zu_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-af_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-am_AM-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ar_AR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-az_AZ-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-bg_BG-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-bn_BN-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ca_ES-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-cop_EG-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-csb_CSB-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-cs_CZ-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-cy_GB-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-da_DK-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-de_AT-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-de_CH-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-de_DE-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-el_GR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-en_AU-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-en_CA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-en_GB-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-en_NZ-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-en_US-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-en_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-eo_EO-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-es_ES-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-es_MX-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-et_EE-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-eu_ES-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fa_FA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fa_IR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fi_FI-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fj_FJ-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fo_FO-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fr_BE-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fr_FR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fur_IT-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-fy_NL-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ga_IE-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-gd_GB-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-gl_ES-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-gsc_FR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-he_IL-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-hi_IN-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-hr_HR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-hu_HU-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-hy_AM-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-id_ID-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-is_IS-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-it_IT-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-km_KH-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ku_TR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-la_LA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-lt_LT-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-lv_LV-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-mg_MG-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-mi_NZ-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-mn_MN-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-mr_IN-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ms_MY-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-nb_NO-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ne_NP-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-nl_NL-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-nn_NO-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-nr_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ns_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ny_MW-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-oc_FR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-or_OR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-pa_PA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-pl_PL-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-pt_BR-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-pt_PT-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-qu_BO-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ro_RO-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ru_RU-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-rw_RW-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-sk_SK-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-sl_SI-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ss_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-st_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-sv_SE-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-sw_KE-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-sw_TZ-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ta_TA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-tet_ID-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-th_TH-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-tl_PH-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-tn_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ts_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-uk_UA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-uz_UZ-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-ve_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-vi_VI-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-xh_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"myspell-zu_ZA-1.0.2-19.2mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;


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

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
# Mandrake Linux Security Advisory MDKA-2006:037.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(24514);
  script_version ("$Revision: 1.9 $"); 
  script_cvs_date("$Date: 2012/09/07 00:23:59 $");

  script_name(english:"MDKA-2006:037 : glibc");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Updated glibc packages are being provided to ensure that kernel and
user-space tools are in sync. This update also fixes a bug present on
x86_64 platforms where strncmp() is mis-optimized.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKA-2006:037");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

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

if (rpm_check(reference:"glibc-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-debug-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-devel-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-doc-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-doc-pdf-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-i18ndata-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-profile-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-static-devel-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-utils-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"ldconfig-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-aa-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-af-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-am-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ar-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-as-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-az-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-be-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ber-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-bg-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-bn-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-br-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-bs-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ca-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-cs-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-cy-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-da-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-de-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-dz-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-el-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-en-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-eo-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-es-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-et-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-eu-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-fa-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-fi-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-fo-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-fr-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-fur-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-fy-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ga-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-gd-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-gl-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-gu-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-gv-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ha-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-he-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-hi-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-hr-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-hu-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-hy-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-id-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ig-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ik-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-is-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-it-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-iu-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ja-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ka-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-kk-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-kl-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-km-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-kn-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ko-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ku-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-kw-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ky-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-lg-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-li-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-lo-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-lt-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-lv-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-mi-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-mk-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ml-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-mn-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-mr-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ms-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-mt-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-nds-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ne-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-nl-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-no-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-nr-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-nso-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-oc-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-pa-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-pl-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-pt-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ro-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ru-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-sc-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-se-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-sk-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-sl-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-so-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-sq-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-sr-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ss-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-st-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-sv-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-sw-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ta-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-te-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-tg-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-th-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-tk-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-tl-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-tn-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-tr-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ts-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-tt-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ug-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-uk-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ur-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-uz-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ve-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-vi-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-wa-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-xh-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-yi-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-yo-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-zh-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-zu-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"nptl-devel-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"nscd-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"timezone-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;

if (rpm_check(reference:"glibc-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-debug-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-devel-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-doc-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-doc-pdf-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-i18ndata-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-profile-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-static-devel-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-utils-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"ldconfig-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-aa-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-af-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-am-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ar-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-as-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-az-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-be-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ber-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-bg-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-bn-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-br-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-bs-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ca-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-cs-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-cy-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-da-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-de-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-dz-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-el-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-en-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-eo-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-es-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-et-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-eu-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-fa-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-fi-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-fo-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-fr-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-fur-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-fy-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ga-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-gd-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-gl-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-gu-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-gv-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ha-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-he-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-hi-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-hr-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-hu-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-hy-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-id-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ig-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ik-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-is-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-it-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-iu-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ja-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ka-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-kk-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-kl-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-km-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-kn-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ko-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ku-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-kw-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ky-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-lg-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-li-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-lo-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-lt-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-lv-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-mi-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-mk-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ml-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-mn-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-mr-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ms-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-mt-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-nds-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ne-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-nl-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-no-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-nr-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-nso-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-oc-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-pa-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-pl-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-pt-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ro-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ru-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-sc-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-se-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-sk-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-sl-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-so-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-sq-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-sr-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ss-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-st-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-sv-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-sw-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ta-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-te-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-tg-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-th-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-tk-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-tl-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-tn-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-tr-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ts-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-tt-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ug-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-uk-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ur-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-uz-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-ve-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-vi-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-wa-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-xh-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-yi-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-yo-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-zh-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"locales-zu-2.3.6-3.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"nptl-devel-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"nscd-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"timezone-2.3.6-4.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;


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

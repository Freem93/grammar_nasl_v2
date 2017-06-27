#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0537 and 
# CentOS Errata and Security Advisory 2008:0537 respectively.
#

include("compat.inc");

if (description)
{
  script_id(33366);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/06/28 23:49:37 $");

  script_cve_id("CVE-2008-2152");
  script_osvdb_id(46052);
  script_xref(name:"RHSA", value:"2008:0537");

  script_name(english:"CentOS 4 : openoffice.org2 (CESA-2008:0537)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openoffice.org packages to correct a security issue are now
available for Red Hat Enterprise Linux 4 and Red Hat Enterprise Linux
5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

OpenOffice.org is an office productivity suite that includes desktop
applications such as a word processor, spreadsheet, presentation
manager, formula editor, and drawing program.

Sean Larsson found a heap overflow flaw in the OpenOffice memory
allocator. If a carefully crafted file was opened by a victim, an
attacker could use the flaw to crash OpenOffice.org or, possibly,
execute arbitrary code. (CVE-2008-2152)

All users of OpenOffice.org are advised to upgrade to these updated
packages, which contain a backported fix to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015048.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8cf1dbec"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015049.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?307bc950"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openoffice.org2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-javafilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-af_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-bg_BG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-ca_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-cs_CZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-cy_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-da_DK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-el_GR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-et_EE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-eu_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-fi_FI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-ga_IE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-gl_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-he_IL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-hi_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-hr_HR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-ja_JP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-ko_KR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-lt_LT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-ms_MY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-pa_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-pl_PL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-sk_SK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-sl_SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-sr_CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-ta_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-th_TH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-tr_TR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-zu_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-testtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-base-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-base-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-calc-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-calc-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-core-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-core-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-draw-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-draw-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-emailmerge-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-emailmerge-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-graphicfilter-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-graphicfilter-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-impress-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-impress-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-javafilter-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-javafilter-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-af_ZA-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-af_ZA-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-ar-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-ar-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-bg_BG-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-bg_BG-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-bn-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-bn-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-ca_ES-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-ca_ES-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-cs_CZ-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-cs_CZ-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-cy_GB-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-cy_GB-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-da_DK-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-da_DK-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-de-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-de-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-el_GR-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-el_GR-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-es-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-es-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-et_EE-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-et_EE-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-eu_ES-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-eu_ES-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-fi_FI-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-fi_FI-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-fr-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-fr-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-ga_IE-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-ga_IE-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-gl_ES-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-gl_ES-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-gu_IN-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-gu_IN-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-he_IL-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-he_IL-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-hi_IN-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-hi_IN-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-hr_HR-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-hr_HR-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-hu_HU-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-hu_HU-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-it-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-it-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-ja_JP-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-ja_JP-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-ko_KR-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-ko_KR-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-lt_LT-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-lt_LT-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-ms_MY-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-ms_MY-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-nb_NO-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-nb_NO-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-nl-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-nl-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-nn_NO-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-nn_NO-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-pa_IN-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-pa_IN-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-pl_PL-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-pl_PL-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-pt_BR-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-pt_BR-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-pt_PT-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-pt_PT-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-ru-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-ru-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-sk_SK-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-sk_SK-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-sl_SI-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-sl_SI-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-sr_CS-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-sr_CS-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-sv-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-sv-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-ta_IN-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-ta_IN-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-th_TH-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-th_TH-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-tr_TR-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-tr_TR-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-zh_CN-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-zh_CN-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-zh_TW-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-zh_TW-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-zu_ZA-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-zu_ZA-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-math-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-math-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-pyuno-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-pyuno-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-testtools-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-testtools-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-writer-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-writer-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-xsltfilter-2.0.4-5.7.0.5.0")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-xsltfilter-2.0.4-5.7.0.5.0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

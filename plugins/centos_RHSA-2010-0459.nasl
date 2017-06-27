#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0459 and 
# CentOS Errata and Security Advisory 2010:0459 respectively.
#

include("compat.inc");

if (description)
{
  script_id(47031);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/08/24 14:07:39 $");

  script_cve_id("CVE-2010-0395");
  script_bugtraq_id(40599);
  script_osvdb_id(65203);
  script_xref(name:"RHSA", value:"2010:0459");

  script_name(english:"CentOS 5 : openoffice.org (CESA-2010:0459)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openoffice.org packages that fix one security issue are now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

[Updated 16 June 2010] The packages list in this erratum has been
updated to include missing packages for the 'Red Hat Enterprise Linux
Server - Optional Desktop Productivity Applications' channel. No
changes have been made to the original packages.

OpenOffice.org is an office productivity suite that includes desktop
applications, such as a word processor, spreadsheet application,
presentation manager, formula editor, and a drawing program.

A flaw was found in the way OpenOffice.org enforced a macro security
setting for macros, written in the Python scripting language, that
were embedded in OpenOffice.org documents. If a user were tricked into
opening a specially crafted OpenOffice.org document and previewed the
macro directory structure, it could lead to Python macro execution
even if macro execution was disabled. (CVE-2010-0395)

All users of OpenOffice.org are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue. For
Red Hat Enterprise Linux 4, this erratum provides updated
openoffice.org2 packages. For Red Hat Enterprise Linux 5, this erratum
provides updated openoffice.org packages. All running instances of
OpenOffice.org applications must be restarted for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-June/016729.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c4e8070"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-June/016730.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6507251"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openoffice.org packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-javafilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-af_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-as_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-bg_BG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ca_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-cs_CZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-cy_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-da_DK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-el_GR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-et_EE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-eu_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-fi_FI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ga_IE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-gl_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-he_IL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-hi_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-hr_HR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ja_JP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-kn_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ko_KR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-lt_LT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ml_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-mr_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ms_MY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-nr_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-nso_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-or_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-pa_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-pl_PL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-sk_SK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-sl_SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-sr_CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ss_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-st_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ta_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-te_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-th_TH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-tn_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-tr_TR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ts_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ve_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-xh_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-zu_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-testtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-base-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-calc-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-core-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-draw-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-emailmerge-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-graphicfilter-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-headless-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-impress-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-javafilter-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-af_ZA-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ar-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-as_IN-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-bg_BG-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-bn-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ca_ES-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-cs_CZ-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-cy_GB-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-da_DK-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-de-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-el_GR-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-es-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-et_EE-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-eu_ES-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-fi_FI-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-fr-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ga_IE-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-gl_ES-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-gu_IN-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-he_IL-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-hi_IN-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-hr_HR-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-hu_HU-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-it-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ja_JP-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-kn_IN-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ko_KR-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-lt_LT-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ml_IN-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-mr_IN-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ms_MY-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nb_NO-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nl-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nn_NO-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nr_ZA-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nso_ZA-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-or_IN-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-pa_IN-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-pl_PL-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-pt_BR-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-pt_PT-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ru-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-sk_SK-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-sl_SI-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-sr_CS-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ss_ZA-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-st_ZA-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-sv-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ta_IN-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-te_IN-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-th_TH-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-tn_ZA-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-tr_TR-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ts_ZA-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ur-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ve_ZA-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-xh_ZA-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-zh_CN-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-zh_TW-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-zu_ZA-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-math-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-pyuno-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-sdk-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-sdk-doc-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-testtools-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-ure-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-writer-3.1.1-19.5.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-xsltfilter-3.1.1-19.5.el5_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

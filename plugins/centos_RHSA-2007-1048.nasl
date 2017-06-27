#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1048 and 
# CentOS Errata and Security Advisory 2007:1048 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43661);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/20 13:54:05 $");

  script_cve_id("CVE-2003-0845", "CVE-2007-4575");
  script_bugtraq_id(26703);
  script_osvdb_id(10094, 40548);
  script_xref(name:"RHSA", value:"2007:1048");

  script_name(english:"CentOS 5 : openoffice.org / hsqldb (CESA-2007:1048)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote CentOS host is missing a security update which has been
documented in Red Hat advisory RHSA-2007:1048."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014624.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d31d658"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014625.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af107fe3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hsqldb and / or openoffice.org packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hsqldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hsqldb-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hsqldb-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hsqldb-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-graphicfilter");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-testtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/10/05");
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
if (rpm_check(release:"CentOS-5", reference:"hsqldb-1.8.0.4-3jpp.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"hsqldb-demo-1.8.0.4-3jpp.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"hsqldb-javadoc-1.8.0.4-3jpp.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"hsqldb-manual-1.8.0.4-3jpp.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-base-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-calc-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-core-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-draw-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-emailmerge-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-graphicfilter-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-impress-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-javafilter-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-af_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ar-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-as_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-bg_BG-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-bn-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ca_ES-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-cs_CZ-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-cy_GB-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-da_DK-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-de-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-el_GR-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-es-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-et_EE-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-eu_ES-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-fi_FI-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-fr-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ga_IE-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-gl_ES-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-gu_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-he_IL-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-hi_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-hr_HR-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-hu_HU-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-it-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ja_JP-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-kn_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ko_KR-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-lt_LT-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ml_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-mr_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ms_MY-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nb_NO-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nl-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nn_NO-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nr_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nso_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-or_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-pa_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-pl_PL-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-pt_BR-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-pt_PT-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ru-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-sk_SK-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-sl_SI-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-sr_CS-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ss_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-st_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-sv-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ta_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-te_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-th_TH-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-tn_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-tr_TR-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ts_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ur-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ve_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-xh_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-zh_CN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-zh_TW-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-zu_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-math-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-pyuno-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-testtools-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-writer-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-xsltfilter-2.0.4-5.4.25")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

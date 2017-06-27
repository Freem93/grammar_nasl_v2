#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update moodle-2387.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(46233);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/06/13 19:55:04 $");

  script_cve_id("CVE-2010-1613", "CVE-2010-1614", "CVE-2010-1615", "CVE-2010-1616", "CVE-2010-1617", "CVE-2010-1618", "CVE-2010-1619");

  script_name(english:"openSUSE Security Update : moodle (openSUSE-SU-2010:0212-1)");
  script_summary(english:"Check for the moodle-2387 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Moodle version 1.9.8 fixes several security issues including
cross-site-scripting (XSS) and SQL injection bugs (CVE-2010-1613,
CVE-2010-1614, CVE-2010-1615, CVE-2010-1616, CVE-2010-1617
CVE-2010-1618, CVE-2010-1619)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-05/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=591850"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected moodle packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-de_du");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-mi_tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-so");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-tl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:moodle-zh_cn");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"moodle-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-af-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-ar-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-be-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-bg-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-bs-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-ca-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-cs-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-da-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-de-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-de_du-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-el-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-es-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-et-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-eu-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-fa-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-fi-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-fr-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-ga-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-gl-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-he-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-hi-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-hr-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-hu-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-id-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-is-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-it-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-ja-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-ka-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-km-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-kn-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-ko-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-lt-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-lv-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-mi_tn-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-ms-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-nl-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-nn-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-no-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-pl-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-pt-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-ro-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-ru-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-sk-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-sl-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-so-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-sq-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-sr-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-sv-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-th-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-tl-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-tr-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-uk-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-vi-1.9.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"moodle-zh_cn-1.9.8-0.1.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "moodle / moodle-af / moodle-ar / moodle-be / moodle-bg / moodle-bs / etc");
}

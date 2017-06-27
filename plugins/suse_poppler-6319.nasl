#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update poppler-6319.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(42030);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/22 20:42:28 $");

  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0755", "CVE-2009-0756", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");

  script_name(english:"openSUSE 10 Security Update : poppler (poppler-6319)");
  script_summary(english:"Check for the poppler-6319 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of poppler: fix various security bugs that occur while
decoding JBIG2 (CVE-2009-0146, CVE-2009-0147, CVE-2009-0165,
CVE-2009-0166, CVE-2009-0799, CVE-2009-0800, CVE-2009-1179,
CVE-2009-1180, CVE-2009-1181, CVE-2009-1182, CVE-2009-1183).

Further a denial of service bug in function
FormWidgetChoice::loadDefaults() (CVE-2009-0755) and
JBIG2Stream::readSymbolDictSeg() (CVE-2009-0756) was closed that could
be triggered via malformed PDF files."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected poppler packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-qt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"poppler-0.5.4-101.6") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"poppler-devel-0.5.4-101.6") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"poppler-glib-0.5.4-101.6") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"poppler-qt-0.5.4-101.6") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"poppler-qt4-0.5.4-101.6") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"poppler-tools-0.5.4-101.6") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler");
}

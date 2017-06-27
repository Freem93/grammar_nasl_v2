#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-508.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99648);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/28 13:38:34 $");

  script_cve_id("CVE-2017-5057", "CVE-2017-5058", "CVE-2017-5059", "CVE-2017-5060", "CVE-2017-5061", "CVE-2017-5062", "CVE-2017-5063", "CVE-2017-5064", "CVE-2017-5065", "CVE-2017-5066", "CVE-2017-5067", "CVE-2017-5069");
  script_xref(name:"IAVB", value:"2017-B-0047");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2017-508)");
  script_summary(english:"Check for the openSUSE-2017-508 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to Chromium 58.0.3029.81 fixes the following security
issues (bsc#1035103) :

  - CVE-2017-5057: Type confusion in PDFium

  - CVE-2017-5058: Heap use after free in Print Preview

  - CVE-2017-5059: Type confusion in Blink

  - CVE-2017-5060: URL spoofing in Omnibox

  - CVE-2017-5061: URL spoofing in Omnibox

  - CVE-2017-5062: Use after free in Chrome Apps

  - CVE-2017-5063: Heap overflow in Skia

  - CVE-2017-5064: Use after free in Blink

  - CVE-2017-5065: Incorrect UI in Blink

  - CVE-2017-5066: Incorrect signature handing in Networking

  - CVE-2017-5067: URL spoofing in Omnibox

  - CVE-2017-5069: Cross-origin bypass in Blink"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035103"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/25");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-58.0.3029.81-111.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-debuginfo-58.0.3029.81-111.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-58.0.3029.81-111.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debuginfo-58.0.3029.81-111.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debugsource-58.0.3029.81-111.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromedriver-58.0.3029.81-104.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromedriver-debuginfo-58.0.3029.81-104.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-58.0.3029.81-104.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-debuginfo-58.0.3029.81-104.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-debugsource-58.0.3029.81-104.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}

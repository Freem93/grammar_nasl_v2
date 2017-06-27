#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-353.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97817);
  script_version("$Revision: 3.6 $");
  script_cvs_date("$Date: 2017/05/01 13:40:21 $");

  script_cve_id("CVE-2017-5029", "CVE-2017-5030", "CVE-2017-5031", "CVE-2017-5032", "CVE-2017-5033", "CVE-2017-5034", "CVE-2017-5035", "CVE-2017-5036", "CVE-2017-5037", "CVE-2017-5038", "CVE-2017-5039", "CVE-2017-5040", "CVE-2017-5041", "CVE-2017-5042", "CVE-2017-5043", "CVE-2017-5044", "CVE-2017-5045", "CVE-2017-5046");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2017-353)");
  script_summary(english:"Check for the openSUSE-2017-353 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 57.0.2987.98 to fix security issues and bugs.

The following vulnerabilities were fixed (bsc#1028848) :

  - CVE-2017-5030: Memory corruption in V8

  - CVE-2017-5031: Use after free in ANGLE

  - CVE-2017-5032: Out of bounds write in PDFium

  - CVE-2017-5029: Integer overflow in libxslt

  - CVE-2017-5034: Use after free in PDFium

  - CVE-2017-5035: Incorrect security UI in Omnibox

  - CVE-2017-5036: Use after free in PDFium

  - CVE-2017-5037: Multiple out of bounds writes in
    ChunkDemuxer

  - CVE-2017-5039: Use after free in PDFium

  - CVE-2017-5040: Information disclosure in V8

  - CVE-2017-5041: Address spoofing in Omnibox

  - CVE-2017-5033: Bypass of Content Security Policy in
    Blink

  - CVE-2017-5042: Incorrect handling of cookies in Cast

  - CVE-2017-5038: Use after free in GuestView

  - CVE-2017-5043: Use after free in GuestView

  - CVE-2017-5044: Heap overflow in Skia

  - CVE-2017-5045: Information disclosure in XSS Auditor

  - CVE-2017-5046: Information disclosure in Blink

The following non-security changes are included :

  - Address broken rendering on non-intel cards"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028848"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/20");
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

if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-57.0.2987.98-105.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-debuginfo-57.0.2987.98-105.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-57.0.2987.98-105.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debuginfo-57.0.2987.98-105.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debugsource-57.0.2987.98-105.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromedriver-57.0.2987.98-105.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromedriver-debuginfo-57.0.2987.98-105.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-57.0.2987.98-105.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-debuginfo-57.0.2987.98-105.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-debugsource-57.0.2987.98-105.2") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}

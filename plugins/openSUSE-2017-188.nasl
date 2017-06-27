#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-188.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96941);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/03/15 21:22:53 $");

  script_cve_id("CVE-2017-5373", "CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5378", "CVE-2017-5380", "CVE-2017-5383", "CVE-2017-5390", "CVE-2017-5396");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2017-188)");
  script_summary(english:"Check for the openSUSE-2017-188 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to Mozilla Thunderbird 45.7.0 fixes security issues and
bugs.

The following security issues from advisory MFSA 2017-03 were fixed
(boo#1021991) In general, these flaws cannot be exploited through
email in Thunderbird because scripting is disabled when reading mail,
but are potentially risks in browser or browser-like contexts :

  - CVE-2017-5375: Excessive JIT code allocation allows
    bypass of ASLR and DEP (boo#1021814)

  - CVE-2017-5376: Use-after-free in XSL (boo#1021817)

  - CVE-2017-5378: Pointer and frame data leakage of
    JavaScript objects (boo#1021818)

  - CVE-2017-5380: Potential use-after-free during DOM
    manipulations (boo#1021819)

  - CVE-2017-5390: Insecure communication methods in
    Developer Tools JSON viewer (boo#1021820)

  - CVE-2017-5396: Use-after-free with Media Decoder
    (boo#1021821)

  - CVE-2017-5383: Location bar spoofing with unicode
    characters (boo#1021822)

  - CVE-2017-5373: Memory safety bugs fixed in Thunderbird
    45.7 (boo#1021824)

The following non-security bugs were fixed :

  - Message preview pane non-functional after IMAP folder
    was renamed or moved

  - 'Move To' button on 'Search Messages' panel not working

  - Message sent to 'undisclosed recipients' shows no
    recipient (non-functional since Thunderbird version 38)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021991"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/02");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-45.7.0-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-buildsymbols-45.7.0-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-debuginfo-45.7.0-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-debugsource-45.7.0-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-devel-45.7.0-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-translations-common-45.7.0-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-translations-other-45.7.0-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"MozillaThunderbird-45.7.0-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"MozillaThunderbird-buildsymbols-45.7.0-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"MozillaThunderbird-debuginfo-45.7.0-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"MozillaThunderbird-debugsource-45.7.0-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"MozillaThunderbird-devel-45.7.0-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"MozillaThunderbird-translations-common-45.7.0-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"MozillaThunderbird-translations-other-45.7.0-34.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / MozillaThunderbird-buildsymbols / etc");
}

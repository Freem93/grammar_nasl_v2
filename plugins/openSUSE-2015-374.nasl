#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-374.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83800);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/26 13:52:13 $");

  script_cve_id("CVE-2011-3079", "CVE-2015-0797", "CVE-2015-2708", "CVE-2015-2710", "CVE-2015-2713", "CVE-2015-2716");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2015-374)");
  script_summary(english:"Check for the openSUSE-2015-374 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla Thunderbird email, news, and chat client was updated to
version 31.7.0 to fix several security issues.

The following vulnerabilities were fixed (bnc#930622) :

  - MFSA 2015-46/CVE-2015-2708 Miscellaneous memory safety
    hazards

  - MFSA 2015-47/CVE-2015-0797 (bmo#1080995) Buffer overflow
    parsing H.264 video with Linux Gstreamer

  - MFSA 2015-48/CVE-2015-2710 (bmo#1149542) Buffer overflow
    with SVG content and CSS

  - MFSA 2015-51/CVE-2015-2713 (bmo#1153478) Use-after-free
    during text processing with vertical text enabled

  - MFSA 2015-54/CVE-2015-2716 (bmo#1140537) Buffer overflow
    when parsing compressed XML

  - MFSA 2015-57/CVE-2011-3079 (bmo#1087565) Privilege
    escalation through IPC channel messages"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=930622"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-31.7.0-70.53.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-buildsymbols-31.7.0-70.53.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debuginfo-31.7.0-70.53.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debugsource-31.7.0-70.53.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-devel-31.7.0-70.53.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-common-31.7.0-70.53.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-other-31.7.0-70.53.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-31.7.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-buildsymbols-31.7.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debuginfo-31.7.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debugsource-31.7.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-devel-31.7.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-common-31.7.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-other-31.7.0-18.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / MozillaThunderbird-buildsymbols / etc");
}

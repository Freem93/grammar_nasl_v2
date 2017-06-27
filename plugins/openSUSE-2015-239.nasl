#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-239.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(81945);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/20 13:22:39 $");

  script_cve_id("CVE-2014-9638", "CVE-2014-9639");

  script_name(english:"openSUSE Security Update : vorbis-tools (openSUSE-2015-239)");
  script_summary(english:"Check for the openSUSE-2015-239 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"vorbis-tools was updated to fix division by zero and integer overflow
by crafted WAV files (CVE-2014-9638, CVE-2014-9639, bnc#914439,
bnc#914441)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=914439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=914441"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected vorbis-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vorbis-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vorbis-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vorbis-tools-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vorbis-tools-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/19");
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

if ( rpm_check(release:"SUSE13.1", reference:"vorbis-tools-1.4.0-14.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vorbis-tools-debuginfo-1.4.0-14.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vorbis-tools-debugsource-1.4.0-14.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vorbis-tools-lang-1.4.0-14.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vorbis-tools-1.4.0-17.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vorbis-tools-debuginfo-1.4.0-17.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vorbis-tools-debugsource-1.4.0-17.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vorbis-tools-lang-1.4.0-17.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vorbis-tools / vorbis-tools-debuginfo / vorbis-tools-debugsource / etc");
}

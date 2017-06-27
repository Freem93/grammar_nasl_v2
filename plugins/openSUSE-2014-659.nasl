#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-659.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79226);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/13 12:11:52 $");

  script_cve_id("CVE-2014-8483");

  script_name(english:"openSUSE Security Update : konversation (openSUSE-SU-2014:1406-1)");
  script_summary(english:"Check for the openSUSE-2014-659 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"konversation was updated to version 1.5.1, fixing bugs and one
security issue.

Changes :

  - Konversation 1.5.1 is a maintenance release containing
    only bug fixes. The included changes address several
    minor behavioral defects and a low-risk DoS security
    defect in the Blowfish ECB support. The KDE Platform
    version dependency has increased to v4.9.0 to gain
    access to newer Qt socket transport security flags.

  - Fixed a bug causing wildcards in command alias
    replacement patterns not to be expanded.

  - Fixed a bug causing auto-joining of channels not
    starting in # or & to sometimes fail because the
    auto-join command was generated before we got the
    CHANTYPES pronouncement by the server.

  - Added a size sanity check for incoming Blowfish ECB
    blocks. The blind assumption of incoming blocks being
    the expected 12 bytes could lead to a crash or up to 11
    byte information leak due to an out-of-bounds read.
    CVE-2014-8483.

  - Enabling SSL/TLS support for connections will now
    advertise the protocols Qt considers secure by default,
    instead of being hardcoded to TLSv1.

  - Fixed the bundled 'sysinfo' script not coping with empty
    lines in /etc/os-release.

  - Made disk space info in the bundled 'sysinfo' script
    more robust by forcing the C locale for 'df'.

  - Added an audio player type hint for Cantata to the
    bundled 'media' script.

  - Fixed some minor comparison logic errors turned up by
    static analysis.

  - Konversation now depends on KDE Platform v4.9.0 or
    higher."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-11/msg00046.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902670"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected konversation packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:konversation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:konversation-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:konversation-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:konversation-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"konversation-1.5.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"konversation-debuginfo-1.5.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"konversation-debugsource-1.5.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"konversation-lang-1.5.1-3.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "konversation");
}

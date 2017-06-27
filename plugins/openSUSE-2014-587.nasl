#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-587.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(78452);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/10/24 10:42:16 $");

  script_cve_id("CVE-2014-2576");

  script_name(english:"openSUSE Security Update : claws-mail (openSUSE-SU-2014:1291-1)");
  script_summary(english:"Check for the openSUSE-2014-587 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Update to version 3.10.1(bnc#870858) :

  + Add an account preference to allow automatically
    accepting unknown and changed SSL certificates, if
    they're valid (that is, if the root CA is trusted by the
    distro).

  + RFE 3196, 'When changing quicksearch Search Type, set
    focus to search input box'.

  + PGP/Core plugin: Generate 2048 bit RSA keys.

  + Major code cleanup.

  + Extended claws-mail.desktop with Compose and Receive
    actions.

  + Fix GConf use with newer Glib.

  + Fix the race fix, now preventing the compose window to
    be closed.

  + Fix 'File (null) doesn't exist' error dialog, when
    attaching a non-existing file via --attach

  + Fix spacing in Folderview if the font is far from the
    system font.

  + RSSyl :

  - When parsing RSS 2.0, ignore tags with a namespace
    prefix.

  - Check for existence of xmlNode namespace, to prevent
    NULL pointer crashes.

  + Bugs fixed: claws#2728, claws#2981, claws#3170,
    claws#3179, claws#3201, deb#730050.

  + Updated translations.

  - Drop
    claws-mail-3.10.0_uninitialized_variable_git51af19b.patc
    h as fixed upstream.

This also fixes CVE-2014-2576."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-10/msg00015.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected claws-mail packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"claws-mail-3.10.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"claws-mail-debuginfo-3.10.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"claws-mail-debugsource-3.10.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"claws-mail-devel-3.10.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"claws-mail-lang-3.10.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"claws-mail-3.10.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"claws-mail-debuginfo-3.10.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"claws-mail-debugsource-3.10.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"claws-mail-devel-3.10.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"claws-mail-lang-3.10.1-3.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "claws-mail / claws-mail-debuginfo / claws-mail-debugsource / etc");
}

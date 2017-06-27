#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-602.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86094);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/09/23 14:26:24 $");

  script_cve_id("CVE-2012-4540", "CVE-2015-5234", "CVE-2015-5235");

  script_name(english:"openSUSE Security Update : icedtea-web (openSUSE-2015-602)");
  script_summary(english:"Check for the openSUSE-2015-602 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The icedtea-web java plugin was updated to 1.6.1.

Changes included :

  - Enabled Entry-Point attribute check

  - permissions sandbox and signed app and unsigned app with
    permissions all-permissions now run in sandbox instead
    of not at all.

  - fixed DownloadService

  - comments in deployment.properties now should persists
    load/save

  - fixed bug in caching of files with query

  - fixed issues with recreating of existing shortcut

  - trustAll/trustNone now processed correctly

  - headless no longer shows dialogues

  - RH1231441 Unable to read the text of the buttons of the
    security dialogue

  - Fixed RH1233697 icedtea-web: applet origin spoofing
    (CVE-2015-5235, bsc#944208)

  - Fixed RH1233667 icedtea-web: unexpected permanent
    authorization of unsigned applets (CVE-2015-5234,
    bsc#944209)

  - MissingALACAdialog made available also for unsigned
    applications (but ignoring actual manifest value) and
    fixed

  - NetX

  - fixed issues with -html shortcuts

  - fixed issue with -html receiving garbage in width and
    height

  - PolicyEditor

  - file flag made to work when used standalone

  - file flag and main argument cannot be used in
    combination

  - Fix generation of man-pages with some versions of 'tail'

Also included is the update to 1.6

  - Massively improved offline abilities. Added Xoffline
    switch to force work without inet connection.

  - Improved to be able to run with any JDK

  - JDK 6 and older no longer supported

  - JDK 8 support added (URLPermission granted if
    applicable)

  - JDK 9 supported 

  - Added support for Entry-Point manifest attribute

  - Added KEY_ENABLE_MANIFEST_ATTRIBUTES_CHECK deployment
    property to control scan of Manifest file 

  - starting arguments now accept also -- abbreviations

  - Added new documentation

  - Added support for menu shortcuts - both javaws
    applications/applets and html applets are supported

  - added support for -html switch for javaws. Now you can
    run most of the applets without browser at all

  - Control Panel

  - PR1856: ControlPanel UI improvement for lower
    resolutions (800*600)

  - NetX

  - PR1858: Java Console accepts multi-byte encodings

  - PR1859: Java Console UI improvement for lower
    resolutions (800*600)

  - RH1091563: [abrt] icedtea-web-1.5-2.fc20: Uncaught
    exception java.lang.ClassCastException in method
    sun.applet.PluginAppletViewer$8.run()

  - Dropped support for long unmaintained -basedir argument

  - Returned support for -jnlp argument

  - RH1095311, PR574 - References class sun.misc.Ref removed
    in OpenJDK 9 - fixed, and so buildable on JDK9

  - Plugin

  - PR1743 - Intermittant deadlock in PluginRequestProcessor

  - PR1298 - LiveConnect - problem setting array elements
    (applet variables) from JS

  - RH1121549: coverity defects

  - Resolves method overloading correctly with superclass
    heirarchy distance

  - PolicyEditor

  - codebases can be renamed in-place, copied, and pasted

  - codebase URLs can be copied to system clipboard

  - displays a progress dialog while opening or saving files

  - codebases without permissions assigned save to file
    anyway (and re-appear on next open)

  - PR1776: NullPointer on save-and-exit

  - PR1850: duplicate codebases when launching from security
    dialogs

  - Fixed bug where clicking 'Cancel' on the 'Save before
    Exiting' dialog could result in the editor exiting
    without saving changes

  - Keyboard accelerators and mnemonics greatly improved

  - 'File - New' allows editing a new policy without first
    selecting the file to save to

  - Common

  - PR1769: support signed applets which specify Sandbox
    permissions in their manifests

  - Temporary Permissions in security dialog now
    multi-selectable and based on PolicyEditor permissions

  - Update to 1.5.2

  - NetX

  - RH1095311, PR574 - References class sun.misc.Ref removed
    in OpenJDK 9 - fixed, and so buildable on JDK9

  - RH1154177 - decoded file needed from cache

  - fixed NPE in https dialog

  - empty codebase behaves as '.'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=755054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=830880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=944208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=944209"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icedtea-web packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-plugin-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-plugin-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/23");
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

if ( rpm_check(release:"SUSE13.1", reference:"icedtea-web-1.5.3-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icedtea-web-debuginfo-1.5.3-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icedtea-web-debugsource-1.5.3-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icedtea-web-javadoc-1.5.3-0.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"icedtea-web-javadoc-1.6.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-plugin-1.6.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-plugin-debuginfo-1.6.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-plugin-debugsource-1.6.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-plugin-1.6.1-6.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-plugin-debuginfo-1.6.1-6.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-plugin-debugsource-1.6.1-6.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-web / icedtea-web-debuginfo / icedtea-web-debugsource / etc");
}

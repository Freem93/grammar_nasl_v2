#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-173.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75270);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2014-0032");

  script_name(english:"openSUSE Security Update : subversion (openSUSE-SU-2014:0307-1)");
  script_summary(english:"Check for the openSUSE-2014-173 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Apache Subversion was updated to version 1.8.8 :

It fix a remotely triggerable segfault in mod_dav_svn when svn is
handling the server root and SVNListParentPath is on [bnc#862459]
CVE-2014-0032

  - Client-side bugfixes :

  - fix automatic relocate for wcs not at repository root

  - wc: improve performance when used with SQLite 3.8

  - copy: fix some scenarios that broke the working copy

  - move: fix errors when moving files between an external
    and the parent working copy

  - log: resolve performance regression in certain scenarios

  - merge: decrease work to detect differences between 3
    files

  - commit: don't change file permissions inappropriately

  - commit: fix assertion due to invalid pool lifetime

  - version: don't cut off the distribution version on Linux

  - flush stdout before exiting to avoid information being
    lost

  - status: fix missing sentinel value on warning codes

  - update/switch: improve some WC db queries that may
    return incorrect results depending on how SQLite is
    built

  - Server-side bugfixes :

  - reduce memory usage during checkout and export

  - fsfs: create rep-cache.db with proper permissions

  - mod_dav_svn: prevent crashes with SVNListParentPath on
    [bnc#862459] CVE-2014-0032

  - mod_dav_svn: fix SVNAllowBulkUpdates directive merging

  - mod_dav_svn: include requested property changes in
    reports

  - svnserve: correct default cache size in help text

  - svnadmin dump: reduce size of dump files with '--deltas'

  - resolve integer underflow that resulted in infinite
    loops

  - developer visible changes :

  - fix ocassional failure of check_tests.py 12

  - fix failure with SQLite 3.8.1-3.8.3 when built with
    SQLITE_ENABLE_STAT3/4 due to bug in SQLite

  - specify SQLite defaults that can be changed when SQLite
    is built to avoid unexpected behavior with Subversion

  - numerous documentation fixes

  - svn_client_commit_item3_dup() fix pool lifetime issues

  - ra_serf: properly ask multiple certificate validation
    providers for acceptance of certificate failures

  - release internal fs objects when closing commit editor

  - svn_client_proplist4() don't call the callback multiple
    times for the same path in order to deliver inherited
    properties

  - Bindings :

  - swig-pl: fix with --enable-sqlite-compatibility-version

  - swig: fix building from tarball with an out-of-tree
    build

  - removed patches :

  - subversion-1.8.x-fix-ppc-tests.patch, committed upstream

  - packaging changes :

  - only require and build with junit when building with
    java and running regression tests

  - 1.8.6 and 1.8.7 were not released"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-02/msg00086.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=862459"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_gnome_keyring-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_gnome_keyring-1-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_kwallet-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_kwallet-1-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libsvn_auth_gnome_keyring-1-0-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsvn_auth_kwallet-1-0-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-bash-completion-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-debuginfo-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-debugsource-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-devel-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-perl-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-perl-debuginfo-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-python-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-python-debuginfo-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-ruby-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-ruby-debuginfo-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-server-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-server-debuginfo-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-tools-1.8.8-2.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-tools-debuginfo-1.8.8-2.21.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "subversion");
}

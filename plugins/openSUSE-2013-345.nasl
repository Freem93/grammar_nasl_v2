#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-345.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74976);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/15 14:55:53 $");

  script_cve_id("CVE-2013-1845", "CVE-2013-1846", "CVE-2013-1847", "CVE-2013-1849", "CVE-2013-1884");
  script_osvdb_id(92090, 92091, 92092, 92093, 92094);

  script_name(english:"openSUSE Security Update : subversion (openSUSE-SU-2013:0687-1)");
  script_summary(english:"Check for the openSUSE-2013-345 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Subversion received minor version updates to fix remote triggerable
vulnerabilities in mod_dav_svn which may result in denial of service.

On openSUSE 12.1 :

  - update to 1.6.21 [bnc#813913], addressing remotely
    triggerable 

  + CVE-2013-1845: mod_dav_svn excessive memory usage from
    property changes

  + CVE-2013-1846: mod_dav_svn crashes on LOCK requests
    against activity URLs

  + CVE-2013-1847: mod_dav_svn crashes on LOCK requests
    against non-existent URLs

  + CVE-2013-1849: mod_dav_svn crashes on PROPFIND requests
    against activity URLs

  - further changes :

  + mod_dav_svn will omit some property values for activity
    urls

  + improve memory usage when committing properties in
    mod_dav_svn

  + fix mod_dav_svn runs pre-revprop-change twice

  + fixed: post-revprop-change errors cancel commit

  + improved logic in mod_dav_svn's implementation of lock.

  + fix a compatibility issue with g++ 4.7

On openSUSE 12.2 and 12.3 :

  - update to 1.7.9 [bnc#813913], addressing remotely
    triggerable vulnerabilities in mod_dav_svn which may
    result in denial of service :

  + CVE-2013-1845: mod_dav_svn excessive memory usage from
    property changes

  + CVE-2013-1846: mod_dav_svn crashes on LOCK requests
    against activity URLs

  + CVE-2013-1847: mod_dav_svn crashes on LOCK requests
    against non-existent URLs

  + CVE-2013-1849: mod_dav_svn crashes on PROPFIND requests
    against activity URLs

  + CVE-2013-1884: mod_dav_svn crashes on out of range limit
    in log REPORT

  - further changes :

  + Client-side bugfixes :

  - improved error messages about svn:date and svn:author
    props.

  - fix local_relpath assertion

  - fix memory leak in `svn log` over svn://

  - fix incorrect authz failure when using neon http library

  - fix segfault when using kwallet

  + Server-side bugfixes :

  - svnserve will log the replayed rev not the low-water
    rev.

  - mod_dav_svn will omit some property values for activity
    urls

  - fix an assertion in mod_dav_svn when acting as a proxy
    on /

  - improve memory usage when committing properties in
    mod_dav_svn

  - fix svnrdump to load dump files with non-LF line endings

  - fix assertion when rep-cache is inaccessible

  - improved logic in mod_dav_svn's implementation of lock.

  - avoid executing unnecessary code in log with limit

  - Developer-visible changes :

  + General :

  - fix an assertion in dav_svn_get_repos_path() on Windows

  - fix get-deps.sh to correctly download zlib

  - doxygen docs will now ignore prefixes when producing the
    index

  - fix get-deps.sh on freebsd

  + Bindings :

  - javahl status api now respects the ignoreExternals
    boolean

  - refresh subversion-no-build-date.patch for upstream
    source changes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-04/msg00095.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813913"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"libsvn_auth_gnome_keyring-1-0-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsvn_auth_kwallet-1-0-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"subversion-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"subversion-debuginfo-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"subversion-debugsource-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"subversion-devel-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"subversion-perl-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"subversion-perl-debuginfo-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"subversion-python-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"subversion-python-debuginfo-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"subversion-ruby-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"subversion-ruby-debuginfo-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"subversion-server-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"subversion-server-debuginfo-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"subversion-tools-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"subversion-tools-debuginfo-1.6.21-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsvn_auth_gnome_keyring-1-0-1.7.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.7.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsvn_auth_kwallet-1-0-1.7.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.7.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-1.7.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-bash-completion-1.7.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-debuginfo-1.7.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-debugsource-1.7.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-devel-1.7.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-perl-1.7.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-perl-debuginfo-1.7.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-python-1.7.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-python-debuginfo-1.7.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-server-1.7.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-server-debuginfo-1.7.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-tools-1.7.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-tools-debuginfo-1.7.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsvn_auth_gnome_keyring-1-0-1.7.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.7.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsvn_auth_kwallet-1-0-1.7.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.7.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-1.7.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-bash-completion-1.7.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-debuginfo-1.7.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-debugsource-1.7.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-devel-1.7.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-perl-1.7.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-perl-debuginfo-1.7.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-python-1.7.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-python-debuginfo-1.7.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-server-1.7.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-server-debuginfo-1.7.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-tools-1.7.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-tools-debuginfo-1.7.9-2.4.1") ) flag++;

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

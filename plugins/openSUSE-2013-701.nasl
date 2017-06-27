#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-701.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75143);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-4277");

  script_name(english:"openSUSE Security Update : subversion (openSUSE-SU-2013:1442-1)");
  script_summary(english:"Check for the openSUSE-2013-701 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This subversion update includes a security fix and several minor
changes.

  - update to 1.7.13 [bnc#836245]

  - User-visible changes :

  - General

  - merge: fix bogus mergeinfo with conflicting file merges

  - diff: fix duplicated path component in '--summarize'
    output

  - ra_serf: ignore case when checking certificate common
    names

  - Server-side bugfixes :

  - svnserve: fix creation of pid files CVE-2013-4277

  - mod_dav_svn: better status codes for commit failures

  - mod_dav_svn: do not map requests to filesystem

  - Developer-visible changes :

  - General :

  - don't use uninitialized variable to produce an error
    code

  - Bindings :

  - swig-pl: fix SVN::Client not honoring config file
    settings

  - swig-pl & swig-py: disable unusable
    svn_fs_set_warning_func"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-09/msg00031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=836245"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/03");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"libsvn_auth_gnome_keyring-1-0-1.7.13-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.7.13-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsvn_auth_kwallet-1-0-1.7.13-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.7.13-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-1.7.13-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-bash-completion-1.7.13-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-debuginfo-1.7.13-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-debugsource-1.7.13-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-devel-1.7.13-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-perl-1.7.13-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-perl-debuginfo-1.7.13-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-python-1.7.13-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-python-debuginfo-1.7.13-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-server-1.7.13-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-server-debuginfo-1.7.13-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-tools-1.7.13-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-tools-debuginfo-1.7.13-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsvn_auth_gnome_keyring-1-0-1.7.13-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.7.13-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsvn_auth_kwallet-1-0-1.7.13-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.7.13-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-1.7.13-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-bash-completion-1.7.13-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-debuginfo-1.7.13-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-debugsource-1.7.13-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-devel-1.7.13-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-perl-1.7.13-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-perl-debuginfo-1.7.13-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-python-1.7.13-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-python-debuginfo-1.7.13-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-server-1.7.13-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-server-debuginfo-1.7.13-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-tools-1.7.13-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-tools-debuginfo-1.7.13-2.16.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsvn_auth_gnome_keyring-1-0 / etc");
}

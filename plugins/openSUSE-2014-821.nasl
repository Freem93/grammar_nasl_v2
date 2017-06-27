#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-821.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80299);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/30 13:40:22 $");

  script_cve_id("CVE-2014-3580", "CVE-2014-8108");

  script_name(english:"openSUSE Security Update : subversion (openSUSE-SU-2014:1725-1)");
  script_summary(english:"Check for the openSUSE-2014-821 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Apache Subversion update fixes the following security and non
security issues.

  - Apache Subversion 1.8.11

  - This release addresses two security issues: [boo#909935]

  - CVE-2014-3580: mod_dav_svn DoS from invalid REPORT
    requests.

  - CVE-2014-8108: mod_dav_svn DoS from use of invalid
    transaction names.

  - Client-side bugfixes :

  - checkout/update: fix file externals failing to follow
    history and subsequently silently failing

  - patch: don't skip targets in valid --git difs

  - diff: make property output in diffs stable

  - diff: fix diff of local copied directory with props

  - diff: fix changelist filter for repos-WC and WC-WC

  - remove broken conflict resolver menu options that always
    error out

  - improve gpg-agent support

  - fix crash in eclipse IDE with GNOME Keyring

  - fix externals shadowing a versioned directory

  - fix problems working on unix file systems that don't
    support permissions

  - upgrade: keep external registrations

  - cleanup: iprove performance of recorded timestamp fixups

  - translation updates for German

  - Server-side bugfixes :

  - disable revprop caching feature due to cache
    invalidation problems

  - skip generating uniquifiers if rep-sharing is not
    supported

  - mod_dav_svn: reject requests with missing repository
    paths

  - mod_dav_svn: reject requests with invalid virtual
    transaction names

  - mod_dav_svn: avoid unneeded memory growth in resource
    walking"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00107.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=909935"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-python-ctypes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/30");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libsvn_auth_gnome_keyring-1-0-1.7.19-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.7.19-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsvn_auth_kwallet-1-0-1.7.19-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.7.19-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-1.7.19-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-bash-completion-1.7.19-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-debuginfo-1.7.19-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-debugsource-1.7.19-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-devel-1.7.19-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-perl-1.7.19-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-perl-debuginfo-1.7.19-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-python-1.7.19-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-python-debuginfo-1.7.19-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-server-1.7.19-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-server-debuginfo-1.7.19-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-tools-1.7.19-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-tools-debuginfo-1.7.19-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsvn_auth_gnome_keyring-1-0-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsvn_auth_kwallet-1-0-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-bash-completion-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-debuginfo-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-debugsource-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-devel-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-perl-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-perl-debuginfo-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-python-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-python-debuginfo-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-ruby-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-ruby-debuginfo-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-server-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-server-debuginfo-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-tools-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-tools-debuginfo-1.8.11-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsvn_auth_gnome_keyring-1-0-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsvn_auth_kwallet-1-0-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-bash-completion-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-debuginfo-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-debugsource-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-devel-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-perl-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-perl-debuginfo-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-python-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-python-ctypes-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-python-debuginfo-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-ruby-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-ruby-debuginfo-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-server-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-server-debuginfo-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-tools-1.8.11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-tools-debuginfo-1.8.11-2.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsvn_auth_gnome_keyring-1-0 / etc");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-289.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(82635);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/10 13:36:30 $");

  script_cve_id("CVE-2015-0202", "CVE-2015-0248", "CVE-2015-0251");

  script_name(english:"openSUSE Security Update : subversion (openSUSE-2015-289)");
  script_summary(english:"Check for the openSUSE-2015-289 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Apache Subversion was updated to 1.8.13 to fix three vulnerabilities
and a number of non-security bugs.

This release fixes three vulnerabilities :

  - Subversion HTTP servers with FSFS repositories were
    vulnerable to a remotely triggerable excessive memory
    use with certain REPORT requests. (bsc#923793
    CVE-2015-0202) 

  - Subversion mod_dav_svn and svnserve were vulnerable to a
    remotely triggerable assertion DoS vulnerability for
    certain requests with dynamically evaluated revision
    numbers. (bsc#923794 CVE-2015-0248)

  - Subversion HTTP servers allow spoofing svn:author
    property values for new revisions (bsc#923795
    CVE-2015-0251)

Non-security fixes :

  - fixes number of client and server side non-security bugs

  - improved working copy performance

  - reduction of resource use

  - stability improvements

  - usability improvements

  - fix sample configuration comments in subversion.conf
    [boo#916286]

  - fix bashisms in mailer-init.sh script"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=916286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=923793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=923794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=923795"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/08");
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

if ( rpm_check(release:"SUSE13.1", reference:"libsvn_auth_gnome_keyring-1-0-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsvn_auth_kwallet-1-0-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-bash-completion-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-debuginfo-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-debugsource-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-devel-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-perl-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-perl-debuginfo-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-python-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-python-debuginfo-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-ruby-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-ruby-debuginfo-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-server-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-server-debuginfo-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-tools-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-tools-debuginfo-1.8.13-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsvn_auth_gnome_keyring-1-0-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsvn_auth_kwallet-1-0-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-bash-completion-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-debuginfo-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-debugsource-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-devel-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-perl-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-perl-debuginfo-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-python-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-python-ctypes-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-python-debuginfo-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-ruby-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-ruby-debuginfo-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-server-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-server-debuginfo-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-tools-1.8.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-tools-debuginfo-1.8.13-2.14.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsvn_auth_gnome_keyring-1-0 / etc");
}

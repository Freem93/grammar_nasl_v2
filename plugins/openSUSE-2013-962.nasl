#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-962.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75226);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-4505", "CVE-2013-4558");
  script_bugtraq_id(63966, 63981);
  script_osvdb_id(100363, 100364);

  script_name(english:"openSUSE Security Update : subversion (openSUSE-SU-2013:1860-1)");
  script_summary(english:"Check for the openSUSE-2013-962 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following issues with subversion :

  - bnc#850747: update to 1.7.14

  - CVE-2013-4505: mod_dontdothat does not restrict requests
    from serf clients.

  - CVE-2013-4558: mod_dav_svn assertion triggered by
    autoversioning commits.

  + Client- and server-side bugfixes :

  - fix assertion on urls of the form 'file://./'

  + Client-side bugfixes :

  - upgrade: fix an assertion when used with pre-1.3 wcs

  - fix externals that point at redirected locations

  - diff: fix incorrect calculation of changes in some cases

  - diff: fix errors with added/deleted targets

  + Server-side bugfixes :

  - mod_dav_svn: Prevent crashes with some 3rd party modules

  - fix OOM on concurrent requests at threaded server start

  - fsfs: limit commit time of files with deep change
    histories

  - mod_dav_svn: canonicalize paths properly

  + Other tool improvements and bugfixes :

  - mod_dontdothat: Fix the uri parser

  + Developer-visible changes :

  - javahl: canonicalize path for streamFileContent method

  + require python-sqlite when running regression tests"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-12/msg00048.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=850667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=850747"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/30");
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

if ( rpm_check(release:"SUSE12.2", reference:"libsvn_auth_gnome_keyring-1-0-1.7.14-4.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.7.14-4.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsvn_auth_kwallet-1-0-1.7.14-4.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.7.14-4.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-1.7.14-4.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-bash-completion-1.7.14-4.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-debuginfo-1.7.14-4.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-debugsource-1.7.14-4.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-devel-1.7.14-4.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-perl-1.7.14-4.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-perl-debuginfo-1.7.14-4.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-python-1.7.14-4.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-python-debuginfo-1.7.14-4.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-server-1.7.14-4.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-server-debuginfo-1.7.14-4.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-tools-1.7.14-4.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"subversion-tools-debuginfo-1.7.14-4.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsvn_auth_gnome_keyring-1-0-1.7.14-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.7.14-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsvn_auth_kwallet-1-0-1.7.14-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.7.14-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-1.7.14-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-bash-completion-1.7.14-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-debuginfo-1.7.14-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-debugsource-1.7.14-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-devel-1.7.14-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-perl-1.7.14-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-perl-debuginfo-1.7.14-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-python-1.7.14-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-python-debuginfo-1.7.14-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-server-1.7.14-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-server-debuginfo-1.7.14-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-tools-1.7.14-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"subversion-tools-debuginfo-1.7.14-2.22.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "subversion");
}

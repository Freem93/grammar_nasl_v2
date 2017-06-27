#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-549.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(85524);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/19 14:23:09 $");

  script_cve_id("CVE-2015-3184", "CVE-2015-3187");

  script_name(english:"openSUSE Security Update : subversion (openSUSE-2015-549)");
  script_summary(english:"Check for the openSUSE-2015-549 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"subversion was updated to version 1.8.14 to fix two security issues.

These security issues were fixed :

  - CVE-2015-3187: Information leak (only paths) that were
    hidden by path-based authz (bsc#939517).

  - CVE-2015-3184: Information leak in mixed
    anonymous/authenticated httpd (dav) configurations
    (bsc#939514)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=939514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=939517"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/19");
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

if ( rpm_check(release:"SUSE13.1", reference:"libsvn_auth_gnome_keyring-1-0-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsvn_auth_kwallet-1-0-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-bash-completion-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-debuginfo-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-debugsource-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-devel-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-perl-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-perl-debuginfo-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-python-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-python-debuginfo-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-ruby-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-ruby-debuginfo-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-server-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-server-debuginfo-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-tools-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"subversion-tools-debuginfo-1.8.14-2.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsvn_auth_gnome_keyring-1-0-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsvn_auth_kwallet-1-0-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-bash-completion-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-debuginfo-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-debugsource-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-devel-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-perl-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-perl-debuginfo-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-python-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-python-ctypes-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-python-debuginfo-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-ruby-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-ruby-debuginfo-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-server-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-server-debuginfo-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-tools-1.8.14-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"subversion-tools-debuginfo-1.8.14-2.17.1") ) flag++;

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

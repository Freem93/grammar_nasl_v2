#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libsvn_auth_gnome_keyring-1-0-4689.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75617);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2011-0715", "CVE-2011-1752", "CVE-2011-1783", "CVE-2011-1921");

  script_name(english:"openSUSE Security Update : libsvn_auth_gnome_keyring-1-0 (openSUSE-SU-2011:0693-1)");
  script_summary(english:"Check for the libsvn_auth_gnome_keyring-1-0-4689 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - CVE-2011-1752: The mod_dav_svn Apache HTTPD server
    module can be crashed though when asked to deliver
    baselined WebDAV resources.

  - CVE-2011-1783: The mod_dav_svn Apache HTTPD server
    module can trigger a loop which consumes all available
    memory on the system.

  - CVE-2011-1921: The mod_dav_svn Apache HTTPD server
    module may leak to remote users the file contents of
    files configured to be unreadable by those users.

  - CVE-2011-0715: Remote attackers could crash an svn
    server by causing a NULL deref"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-06/msg00040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=676949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=688968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=698205"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libsvn_auth_gnome_keyring-1-0 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_gnome_keyring-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_kwallet-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/07");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"libsvn_auth_gnome_keyring-1-0-1.6.9-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libsvn_auth_kwallet-1-0-1.6.9-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"subversion-1.6.9-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"subversion-devel-1.6.9-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"subversion-perl-1.6.9-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"subversion-python-1.6.9-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"subversion-ruby-1.6.9-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"subversion-server-1.6.9-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"subversion-tools-1.6.9-4.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsvn_auth_gnome_keyring-1-0 / libsvn_auth_kwallet-1-0 / etc");
}

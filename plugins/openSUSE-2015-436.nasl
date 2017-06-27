#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-436.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(84335);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2014-9390");

  script_name(english:"openSUSE Security Update : cgit (openSUSE-2015-436)");
  script_summary(english:"Check for the openSUSE-2015-436 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The git web frontend cgit was updated to 0.11.2 to fix security issues
and bugs.

The following vulnerabilities were fixed :

  - CVE-2014-9390: arbitrary command execution vulnerability
    on case-insensitive file systems in git. Malicious
    commits could affect client users on all platforms using
    case-insensitive file systems when using vulnerable git
    versions.

In addition cgit was updated to 0.11.2 with minor improvements and bug
fixes.

The embedded git version was updated to 2.4.3."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910756"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cgit packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Malicious Git and Mercurial HTTP Server For CVE-2014-9390');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cgit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cgit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cgit-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.1", reference:"cgit-0.11.2-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cgit-debuginfo-0.11.2-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cgit-debugsource-0.11.2-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cgit-0.11.2-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cgit-debuginfo-0.11.2-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cgit-debugsource-0.11.2-13.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cgit / cgit-debuginfo / cgit-debugsource");
}

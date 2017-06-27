#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-457.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(84532);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/07/06 13:45:36 $");

  script_cve_id("CVE-2012-6684");

  script_name(english:"openSUSE Security Update : rubygem-RedCloth (openSUSE-2015-457)");
  script_summary(english:"Check for the openSUSE-2015-457 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"rubygem-RedCloth was updated to fix one security issue.

The following vulnerability was fixed :

CVE-2012-6684: A cross-site scripting (XSS) vulnerability allowed
remote attackers to inject arbitrary web script or HTML via a
javascript: URI (boo#912212)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=912212"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rubygem-RedCloth packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-RedCloth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-RedCloth-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-RedCloth-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-RedCloth-testsuite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/06");
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

if ( rpm_check(release:"SUSE13.1", reference:"rubygem-RedCloth-4.2.9-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rubygem-RedCloth-debuginfo-4.2.9-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rubygem-RedCloth-debugsource-4.2.9-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rubygem-RedCloth-testsuite-4.2.9-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rubygem-RedCloth-4.2.9-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rubygem-RedCloth-debuginfo-4.2.9-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rubygem-RedCloth-debugsource-4.2.9-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rubygem-RedCloth-testsuite-4.2.9-7.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rubygem-RedCloth / rubygem-RedCloth-debuginfo / etc");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update gimp-4637.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75514);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2011-1178", "CVE-2011-1782");

  script_name(english:"openSUSE Security Update : gimp (openSUSE-SU-2011:0586-1)");
  script_summary(english:"Check for the gimp-4637 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes various overflows :

  + CVE-2011-1178: CVSS v2 Base Score: 6.8
    (AV:N/AC:M/Au:N/C:P/I:P/A:P)

  + CVE-2011-1782: CVSS v2 Base Score: 6.8
    (AV:N/AC:M/Au:N/C:P/I:P/A:P)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-06/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=692877"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gimp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-help-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-module-hal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-plugins-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/31");
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

if ( rpm_check(release:"SUSE11.3", reference:"gimp-2.6.8-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"gimp-branding-upstream-2.6.8-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"gimp-devel-2.6.8-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"gimp-help-browser-2.6.8-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"gimp-lang-2.6.8-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"gimp-module-hal-2.6.8-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"gimp-plugins-python-2.6.8-7.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp");
}
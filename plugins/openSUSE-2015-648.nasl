#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-648.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86337);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/10/12 13:22:47 $");

  script_cve_id("CVE-2015-1335");

  script_name(english:"openSUSE Security Update : lxc (openSUSE-2015-648)");
  script_summary(english:"Check for the openSUSE-2015-648 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"lxc was update to fix one security issue.

The following vulnerability was fixed :

  - CVE-2015-1335: A directory traversal flaw while
    lxc-start is initially setting up the mounts for a
    container (boo#946744)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=946744"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lxc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxc-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/12");
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

if ( rpm_check(release:"SUSE13.1", reference:"lxc-0.9.0-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lxc-debuginfo-0.9.0-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lxc-debugsource-0.9.0-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lxc-devel-0.9.0-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"lxc-1.0.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"lxc-debuginfo-1.0.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"lxc-debugsource-1.0.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"lxc-devel-1.0.6-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lxc / lxc-debuginfo / lxc-debugsource / lxc-devel");
}

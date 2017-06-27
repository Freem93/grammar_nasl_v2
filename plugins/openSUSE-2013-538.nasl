#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-538.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75060);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2013-2126");
  script_bugtraq_id(60174);

  script_name(english:"openSUSE Security Update : darktable (openSUSE-SU-2013:1083-1)");
  script_summary(english:"Check for the openSUSE-2013-538 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of darktable fixes a problem inside the embedded libraw
version.

  - Fix for CVE-2013-2126

  - added backported patch from git master
    0001-fixed-error-handling-for-broken-full-color-images.p
    atch fixes bnc#823114-"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00193.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823114"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected darktable packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:darktable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:darktable-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:darktable-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.2", reference:"darktable-1.0.5-3.9.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"darktable-debuginfo-1.0.5-3.9.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"darktable-debugsource-1.0.5-3.9.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"darktable-1.1.3-1.5.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"darktable-debuginfo-1.1.3-1.5.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"darktable-debugsource-1.1.3-1.5.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"darktable-1.1.3-1.5.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"darktable-debuginfo-1.1.3-1.5.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"darktable-debugsource-1.1.3-1.5.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "darktable / darktable-debuginfo / darktable-debugsource");
}

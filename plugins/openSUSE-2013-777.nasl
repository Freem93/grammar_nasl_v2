#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-777.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75172);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-4324");
  script_bugtraq_id(62538);
  script_osvdb_id(97508);

  script_name(english:"openSUSE Security Update : spice-gtk (openSUSE-SU-2013:1562-1)");
  script_summary(english:"Check for the openSUSE-2013-777 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"spice-gtk received fixes for the acl helper policy kit checks that had
a race condition in PID checking. (CVE-2013-4324, bnc#844967)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-10/msg00031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=844967"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spice-gtk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-glib-2_0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-glib-2_0-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-glib-2_0-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-glib-2_0-8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-gtk-2_0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-gtk-2_0-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-gtk-2_0-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-gtk-2_0-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-gtk-3_0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-gtk-3_0-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-gtk-3_0-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-gtk-3_0-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-controller0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-controller0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-SpiceClientGtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-SpiceClientGtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-gtk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-gtk-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-SpiceClientGlib-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-SpiceClientGtk-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-SpiceClientGtk-3_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/10");
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

if ( rpm_check(release:"SUSE12.2", reference:"libspice-client-glib-2_0-1-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libspice-client-glib-2_0-1-debuginfo-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libspice-client-gtk-2_0-1-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libspice-client-gtk-2_0-1-debuginfo-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libspice-client-gtk-3_0-1-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libspice-client-gtk-3_0-1-debuginfo-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libspice-controller0-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libspice-controller0-debuginfo-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"python-SpiceClientGtk-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"python-SpiceClientGtk-debuginfo-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"spice-gtk-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"spice-gtk-debuginfo-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"spice-gtk-debugsource-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"spice-gtk-devel-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"spice-gtk-lang-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"typelib-1_0-SpiceClientGlib-2_0-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"typelib-1_0-SpiceClientGtk-2_0-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"typelib-1_0-SpiceClientGtk-3_0-0.12-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libspice-client-glib-2_0-8-0.14-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libspice-client-glib-2_0-8-debuginfo-0.14-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libspice-client-gtk-2_0-4-0.14-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libspice-client-gtk-2_0-4-debuginfo-0.14-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libspice-client-gtk-3_0-4-0.14-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libspice-client-gtk-3_0-4-debuginfo-0.14-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libspice-controller0-0.14-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libspice-controller0-debuginfo-0.14-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-SpiceClientGtk-0.14-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-SpiceClientGtk-debuginfo-0.14-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"spice-gtk-0.14-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"spice-gtk-debuginfo-0.14-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"spice-gtk-debugsource-0.14-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"spice-gtk-devel-0.14-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"spice-gtk-lang-0.14-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"typelib-1_0-SpiceClientGlib-2_0-0.14-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"typelib-1_0-SpiceClientGtk-2_0-0.14-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"typelib-1_0-SpiceClientGtk-3_0-0.14-3.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spice-gtk");
}

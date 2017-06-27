#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update python-cupshelpers-5604.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76002);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2011-2899", "CVE-2011-4405");

  script_name(english:"openSUSE Security Update : python-cupshelpers (openSUSE-SU-2011:1331-2)");
  script_summary(english:"Check for the python-cupshelpers-5604 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a typo from the previous update :

system-config-printer used an unauthenticated connection when
downloading printer drivers from openprinting.org (CVE-2011-4405).
This update disables the printer driver download feature.

system-config-printer did not properly quote shell meta characters in
SMB server or workgroup names when passing them to the shell
(CVE-2011-2899)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-01/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=733542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=735322"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-cupshelpers packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-cupshelpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:system-config-printer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:system-config-printer-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:system-config-printer-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-configure-printer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-configure-printer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/03");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"python-cupshelpers-1.2.5-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"system-config-printer-1.2.5-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"system-config-printer-debugsource-1.2.5-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"system-config-printer-lang-1.2.5-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"udev-configure-printer-1.2.5-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"udev-configure-printer-debuginfo-1.2.5-5.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-cupshelpers / system-config-printer / etc");
}

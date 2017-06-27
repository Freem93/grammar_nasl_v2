#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-227.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97077);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/09 15:07:54 $");

  script_cve_id("CVE-2016-9577", "CVE-2016-9578");

  script_name(english:"openSUSE Security Update : spice (openSUSE-2017-227)");
  script_summary(english:"Check for the openSUSE-2017-227 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update for spice fixes the following issues :

CVE-2016-9577: A buffer overflow in the spice server could have
potentially been used by unauthenticated attackers to execute
arbitrary code. (bsc#1023078) CVE-2016-9578: Unauthenticated attackers
could have caused a denial of service via a crafted message.
(bsc#1023079)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023079"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spice packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-server1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-server1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libspice-server-devel-0.12.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libspice-server1-0.12.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libspice-server1-debuginfo-0.12.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"spice-client-0.12.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"spice-client-debuginfo-0.12.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"spice-debugsource-0.12.5-11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libspice-server-devel / libspice-server1 / etc");
}

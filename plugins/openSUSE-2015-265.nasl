#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-265.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(82423);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/05 13:44:22 $");

  script_cve_id("CVE-2015-2331");

  script_name(english:"openSUSE Security Update : libzip (openSUSE-2015-265)");
  script_summary(english:"Check for the openSUSE-2015-265 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Libzip was updated to fix one security issue.

A zip file with an unusually large number of entries could have caused
an integer overflow leading to a write past the heap boundary,
crashing the application. (CVE-2015-2331 bnc#923240)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=923240"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libzip packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzip-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzip2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzip2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzip2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
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

if ( rpm_check(release:"SUSE13.1", reference:"libzip-0.11.2-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libzip-debuginfo-0.11.2-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libzip-debugsource-0.11.2-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libzip-devel-0.11.2-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libzip2-0.11.2-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libzip2-debuginfo-0.11.2-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libzip-0.11.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libzip-debuginfo-0.11.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libzip-debugsource-0.11.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libzip-devel-0.11.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libzip2-0.11.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libzip2-debuginfo-0.11.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libzip2-32bit-0.11.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libzip2-debuginfo-32bit-0.11.2-3.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libzip / libzip-debuginfo / libzip-debugsource / libzip-devel / etc");
}

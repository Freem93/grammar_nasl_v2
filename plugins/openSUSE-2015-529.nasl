#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-529.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(85186);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/06/27 14:13:07 $");

  script_cve_id("CVE-2015-3246");
  script_xref(name:"IAVA", value:"2015-A-0179");

  script_name(english:"openSUSE Security Update : libuser (openSUSE-2015-529)");
  script_summary(english:"Check for the openSUSE-2015-529 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libuser was updated to fix on security issue.

The following vulnerability was fixed :

  - CVE-2015-3246: local root exploit through passwd file
    handling (boo#937533)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937533"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libuser packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuser-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuser-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuser-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuser-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuser-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuser1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuser1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libuser-0.60-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libuser-debuginfo-0.60-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libuser-debugsource-0.60-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libuser-devel-0.60-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libuser-lang-0.60-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libuser-python-0.60-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libuser-python-debuginfo-0.60-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libuser1-0.60-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libuser1-debuginfo-0.60-3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libuser / libuser-debuginfo / libuser-debugsource / libuser-devel / etc");
}

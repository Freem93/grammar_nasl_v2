#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-280.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(82487);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/05 13:44:22 $");

  script_cve_id("CVE-2014-9709");

  script_name(english:"openSUSE Security Update : gd (openSUSE-2015-280)");
  script_summary(english:"Check for the openSUSE-2015-280 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The graphics drawing library gd was updated to fix one security issue.

The following vulnerability was fixed :

  - possible buffer read overflow (CVE-2014-9709)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=923945"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgd3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgd3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgd3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgd3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/01");
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

if ( rpm_check(release:"SUSE13.1", reference:"gd-2.0.36.RC1-78.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gd-debuginfo-2.0.36.RC1-78.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gd-debugsource-2.0.36.RC1-78.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gd-devel-2.0.36.RC1-78.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"gd-32bit-2.0.36.RC1-78.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"gd-debuginfo-32bit-2.0.36.RC1-78.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gd-2.1.0-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gd-debuginfo-2.1.0-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gd-debugsource-2.1.0-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gd-devel-2.1.0-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgd3-2.1.0-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgd3-debuginfo-2.1.0-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgd3-32bit-2.1.0-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgd3-debuginfo-32bit-2.1.0-7.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gd / gd-32bit / gd-debuginfo / gd-debuginfo-32bit / gd-debugsource / etc");
}

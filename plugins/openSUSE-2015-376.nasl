#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-376.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83802);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/26 13:52:13 $");

  script_cve_id("CVE-2013-4422", "CVE-2015-3427");

  script_name(english:"openSUSE Security Update : quassel (openSUSE-2015-376)");
  script_summary(english:"Check for the openSUSE-2015-376 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The distributed IRC client quassel was updated to fix one security
issue.

The following vulnerability was fixed :

  - CVE-2015-3427: The SQL injection fix for CVE-2013-4422
    was incomplete (boo#928728)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=928728"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected quassel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-mono-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/26");
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

if ( rpm_check(release:"SUSE13.1", reference:"quassel-base-0.9.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"quassel-client-0.9.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"quassel-client-debuginfo-0.9.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"quassel-core-0.9.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"quassel-core-debuginfo-0.9.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"quassel-debugsource-0.9.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"quassel-mono-0.9.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"quassel-mono-debuginfo-0.9.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-base-0.10.0-3.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-client-0.10.0-3.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-client-debuginfo-0.10.0-3.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-core-0.10.0-3.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-core-debuginfo-0.10.0-3.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-debugsource-0.10.0-3.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-mono-0.10.0-3.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-mono-debuginfo-0.10.0-3.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quassel-base / quassel-client / quassel-client-debuginfo / etc");
}

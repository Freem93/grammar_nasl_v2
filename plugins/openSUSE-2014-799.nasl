#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-799.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80212);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/23 13:49:35 $");

  script_cve_id("CVE-2014-9087");

  script_name(english:"openSUSE Security Update : libksba (openSUSE-SU-2014:1682-1)");
  script_summary(english:"Check for the openSUSE-2014-799 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This libksba update fixes the following security issue :

  - bnc#907074: buffer overflow in OID processing
    (CVE-2014-9087)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00081.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=907074"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libksba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksba8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksba8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/23");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libksba-debugsource-1.3.0-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libksba-devel-1.3.0-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libksba8-1.3.0-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libksba8-debuginfo-1.3.0-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libksba-debugsource-1.3.0-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libksba-devel-1.3.0-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libksba8-1.3.0-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libksba8-debuginfo-1.3.0-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libksba-debugsource-1.3.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libksba-devel-1.3.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libksba8-1.3.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libksba8-debuginfo-1.3.1-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libksba-debugsource / libksba-devel / libksba8 / libksba8-debuginfo");
}

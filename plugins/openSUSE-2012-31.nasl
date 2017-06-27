#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-31.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74649);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_name(english:"openSUSE Security Update : rubygem-actionmailer-2_3 / rubygem-actionpack-2_3 / rubygem-activerecord-2_3 / etc (openSUSE-2012-31)");
  script_summary(english:"Check for the openSUSE-2012-31 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:"Rails update to version 2.3.14 to fix security issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712062"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rubygem-actionmailer-2_3 / rubygem-actionpack-2_3 / rubygem-activerecord-2_3 / etc packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionmailer-2_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionmailer-2_3-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionpack-2_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionpack-2_3-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activerecord-2_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activerecord-2_3-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activeresource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activeresource-2_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activeresource-2_3-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activesupport-2_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-rails-2_3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/17");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionmailer-2.3.14-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionmailer-2_3-2.3.14-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionmailer-2_3-testsuite-2.3.14-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionpack-2.3.14-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionpack-2_3-2.3.14-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionpack-2_3-testsuite-2.3.14-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activerecord-2.3.14-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activerecord-2_3-2.3.14-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activerecord-2_3-testsuite-2.3.14-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activeresource-2.3.14-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activeresource-2_3-2.3.14-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activeresource-2_3-testsuite-2.3.14-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activesupport-2.3.14-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activesupport-2_3-2.3.14-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-rails-2.3.14-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-rails-2_3-2.3.14-3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rubygem-actionmailer-2_3 / rubygem-actionmailer-2_3-testsuite / etc");
}

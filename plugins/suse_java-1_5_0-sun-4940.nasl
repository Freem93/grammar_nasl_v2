#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update java-1_5_0-sun-4940.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(30195);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/13 20:11:35 $");

  script_name(english:"openSUSE 10 Security Update : java-1_5_0-sun (java-1_5_0-sun-4940)");
  script_summary(english:"Check for the java-1_5_0-sun-4940 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update brings SUN Java 1.5.0 to update14. The security
issues fixed are not yset publically known, but it fixes several ones.

It also contains timezone update 2007k."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_5_0-sun packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"java-1_5_0-sun-1.5.0_14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_5_0-sun-alsa-1.5.0_14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_5_0-sun-demo-1.5.0_14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_5_0-sun-devel-1.5.0_14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_5_0-sun-jdbc-1.5.0_14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_5_0-sun-plugin-1.5.0_14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_5_0-sun-src-1.5.0_14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_5_0-sun-1.5.0_update14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_5_0-sun-alsa-1.5.0_update14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_5_0-sun-demo-1.5.0_update14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_5_0-sun-devel-1.5.0_update14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_5_0-sun-jdbc-1.5.0_update14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_5_0-sun-plugin-1.5.0_update14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_5_0-sun-src-1.5.0_update14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_5_0-sun-1.5.0_update14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_5_0-sun-alsa-1.5.0_update14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_5_0-sun-demo-1.5.0_update14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_5_0-sun-devel-1.5.0_update14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_5_0-sun-jdbc-1.5.0_update14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_5_0-sun-plugin-1.5.0_update14-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_5_0-sun-src-1.5.0_update14-0.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_5_0-sun");
}

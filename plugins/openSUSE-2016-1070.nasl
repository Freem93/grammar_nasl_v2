#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1070.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93433);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2016-5384");

  script_name(english:"openSUSE Security Update : fontconfig (openSUSE-2016-1070)");
  script_summary(english:"Check for the openSUSE-2016-1070 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for fontconfig fixes the following issues :

  - security update :

  - CVE-2016-5384: Possible double free due to
    insufficiently validated cache files [bsc#992534]

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=992534"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected fontconfig packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fontconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fontconfig-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fontconfig-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fontconfig-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fontconfig-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fontconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fontconfig-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.1", reference:"fontconfig-2.11.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"fontconfig-debuginfo-2.11.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"fontconfig-debugsource-2.11.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"fontconfig-devel-2.11.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"fontconfig-32bit-2.11.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"fontconfig-debuginfo-32bit-2.11.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"fontconfig-devel-32bit-2.11.0-5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fontconfig / fontconfig-32bit / fontconfig-debuginfo / etc");
}

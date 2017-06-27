#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update flac-4571.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27530);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/06/13 20:06:06 $");

  script_cve_id("CVE-2007-4619");

  script_name(english:"openSUSE 10 Security Update : flac (flac-4571)");
  script_summary(english:"Check for the flac-4571 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple integer overflows in flac could potentially be exploited by
attackers via specially crafted files to execute code in the context
of the user opening the file (CVE-2007-4619)."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected flac packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libFLAC++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libFLAC++6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libFLAC8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libFLAC8-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE10.1", reference:"flac-1.1.2-15.7") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"flac-devel-1.1.2-15.7") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"flac-32bit-1.1.2-15.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"flac-1.1.2-36") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"flac-devel-1.1.2-36") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"flac-32bit-1.1.2-36") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"flac-1.2.0-13.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"flac-devel-1.2.0-13.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libFLAC++6-1.2.0-13.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libFLAC8-1.2.0-13.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"libFLAC++6-32bit-1.2.0-13.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"libFLAC8-32bit-1.2.0-13.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flac / flac-32bit / flac-devel / libFLAC++6 / libFLAC++6-32bit / etc");
}

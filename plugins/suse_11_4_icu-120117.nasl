#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update icu-5658.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75866);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2010-4409", "CVE-2011-4599");
  script_osvdb_id(69651, 77698);

  script_name(english:"openSUSE Security Update : icu (openSUSE-SU-2012:0100-1)");
  script_summary(english:"Check for the icu-5658 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted strings could cause a buffer overflow in icu
(CVE-2011-4599).

An integer overflow in the getSymbol() function could crash
applications using icu (CVE-2010-4409)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-01/msg00035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=657910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=736146"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected icu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icu-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libicu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libicu-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libicu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libicu-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libicu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libicu-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"icu-4.4.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"icu-data-4.4.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"icu-debuginfo-4.4.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"icu-debugsource-4.4.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libicu-4.4.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libicu-debuginfo-4.4.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libicu-devel-4.4.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libicu-32bit-4.4.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libicu-debuginfo-32bit-4.4.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libicu-devel-32bit-4.4.2-4.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icu / icu-data / libicu / libicu-32bit / libicu-devel / etc");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaThunderbird-2734.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27129);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2007-0008", "CVE-2007-0775", "CVE-2007-0776", "CVE-2007-0777");

  script_name(english:"openSUSE 10 Security Update : MozillaThunderbird (MozillaThunderbird-2734)");
  script_summary(english:"Check for the MozillaThunderbird-2734 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla Thunderbird to version 1.5.0.10. It
contains stability fixes and some security fixes :

  - MFSA 2007-01: As part of the Thunderbird 1.5.0.10 update
    releases several bugs were fixed to improve the
    stability of the browser. Some of these were crashes
    that showed evidence of memory corruption and we presume
    that with enough effort at least some of these could be
    exploited to run arbitrary code. These fixes affected
    the layout engine (CVE-2007-0775), SVG renderer
    (CVE-2007-0776) and JavaScript engine (CVE-2007-0777).

  - MFSA 2007-06: CVE-2007-0008: SSL clients such as Firefox
    and Thunderbird can suffer a buffer overflow if a
    malicious server presents a certificate with a public
    key that is too small to encrypt the entire 'Master
    Secret'. Exploiting this overflow appears to be
    unreliable but possible if the SSLv2 protocol is
    enabled."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"MozillaThunderbird-1.5.0.10-1.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"MozillaThunderbird-translations-1.5.0.10-1.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"MozillaThunderbird-1.5.0.10-1.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"MozillaThunderbird-translations-1.5.0.10-1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaThunderbird-6347.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(41985);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-1307", "CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1836", "CVE-2009-1838", "CVE-2009-1841");

  script_name(english:"openSUSE 10 Security Update : MozillaThunderbird (MozillaThunderbird-6347)");
  script_summary(english:"Check for the MozillaThunderbird-6347 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Thunderbird was updated to the 2.0.0.22 security release. It
fixes various bugs and security issues :

  - MFSA-2009-14/CVE-2009-1302/CVE-2009-1303/CVE-2009-1304
    CVE-2009-1305 Crashes with evidence of memory corruption
    (rv:1.9.0.9)

  - MFSA 2009-17/CVE-2009-1307 (bmo#481342) Same-origin
    violations when Adobe Flash loaded via view-source:
    scheme

  - MFSA 2009-24/CVE-2009-1392/CVE-2009-1832/CVE-2009-1833
    Crashes with evidence of memory corruption (rv:1.9.0.11)

  - MFSA 2009-27/CVE-2009-1836 (bmo#479880) SSL tampering
    via non-200 responses to proxy CONNECT requests

  - MFSA 2009-29/CVE-2009-1838 (bmo#489131) Arbitrary code
    execution using event listeners attached to an element
    whose owner document is null

  - MFSA 2009-32/CVE-2009-1841 (bmo#479560) JavaScript
    chrome privilege escalation

  - MFSA 2009-33 (bmo#495057) Crash viewing
    multipart/alternative message with text/enhanced part"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 94, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"MozillaThunderbird-2.0.0.22-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"MozillaThunderbird-devel-2.0.0.22-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"MozillaThunderbird-translations-2.0.0.22-0.1") ) flag++;

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

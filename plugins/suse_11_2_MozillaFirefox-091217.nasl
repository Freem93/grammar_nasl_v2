#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-1708.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(43383);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 20:21:19 $");

  script_cve_id("CVE-2009-3388", "CVE-2009-3389", "CVE-2009-3979", "CVE-2009-3980", "CVE-2009-3982", "CVE-2009-3983", "CVE-2009-3984", "CVE-2009-3985", "CVE-2009-3986");

  script_name(english:"openSUSE Security Update : MozillaFirefox (MozillaFirefox-1708)");
  script_summary(english:"Check for the MozillaFirefox-1708 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla Firefox was updated to version 3.5.6, fixing lots of bugs
and various security issues.

The following issues were fixed :

  - MFSA 2009-65/CVE-2009-3979/CVE-2009-3980/CVE-2009-3982
    Crashes with evidence of memory corruption (rv:1.9.1.6)

  - MFSA 2009-66/CVE-2009-3388 (bmo#504843,bmo#523816)
    Memory safety fixes in liboggplay media library

  - MFSA 2009-67/CVE-2009-3389 (bmo#515882,bmo#504613)
    Integer overflow, crash in libtheora video library

  - MFSA 2009-68/CVE-2009-3983 (bmo#487872) NTLM reflection
    vulnerability

  - MFSA 2009-69/CVE-2009-3984/CVE-2009-3985
    (bmo#521461,bmo#514232) Location bar spoofing
    vulnerabilities

  - MFSA 2009-70/CVE-2009-3986 (bmo#522430) Privilege
    escalation via chrome window.opener"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=559807"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-gnomevfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-xpcom191");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/22");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"MozillaFirefox-3.5.6-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"MozillaFirefox-branding-upstream-3.5.6-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"MozillaFirefox-translations-common-3.5.6-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"MozillaFirefox-translations-other-3.5.6-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-1.9.1.6-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-devel-1.9.1.6-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.6-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-translations-common-1.9.1.6-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-translations-other-1.9.1.6-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"python-xpcom191-1.9.1.6-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.6-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.6-1.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}

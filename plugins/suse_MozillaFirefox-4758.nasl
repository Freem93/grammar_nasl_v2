#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-4758.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(28369);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2007-5947", "CVE-2007-5959", "CVE-2007-5960");

  script_name(english:"openSUSE 10 Security Update : MozillaFirefox (MozillaFirefox-4758)");
  script_summary(english:"Check for the MozillaFirefox-4758 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla Firefox to security update version 2.0.0.10

Following security problems were fixed: MFSA 2007-37 / CVE-2007-5947:
The jar protocol handler in Mozilla Firefox retrieves the inner URL
regardless of its MIME type, and considers HTML documents within a jar
archive to have the same origin as the inner URL, which allows remote
attackers to conduct cross-site scripting (XSS) attacks via a jar:
URI.

MFSA 2007-38 / CVE-2007-5959: The Firefox 2.0.0.10 update contains
fixes for three bugs that improve the stability of the product. These
crashes showed some evidence of memory corruption under certain
circumstances and we presume that with enough effort at least some of
these could be exploited to run arbitrary code.

MFSA 2007-39 / CVE-2007-5960: Gregory Fleischer demonstrated that it
was possible to generate a fake HTTP Referer header by exploiting a
timing condition when setting the window.location property. This could
be used to conduct a Cross-site Request Forgery (CSRF) attack against
websites that rely only on the Referer header as protection against
such attacks."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/30");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"MozillaFirefox-2.0.0.10-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"MozillaFirefox-translations-2.0.0.10-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"MozillaFirefox-2.0.0.10-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"MozillaFirefox-translations-2.0.0.10-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"MozillaFirefox-2.0.0.10-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"MozillaFirefox-translations-2.0.0.10-0.1") ) flag++;

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

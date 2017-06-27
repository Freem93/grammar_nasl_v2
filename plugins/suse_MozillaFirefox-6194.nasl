#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-6194.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(36199);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2009-0040", "CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0772", "CVE-2009-0774", "CVE-2009-0776", "CVE-2009-1169");

  script_name(english:"openSUSE 10 Security Update : MozillaFirefox (MozillaFirefox-6194)");
  script_summary(english:"Check for the MozillaFirefox-6194 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla Firefox Browser was refreshed to the current MOZILLA_1_8
branch state around fix level 2.0.0.22. 

Security issues identified as being fixed are: MFSA 2009-01 /
CVE-2009-0352 / CVE-2009-0353: Mozilla developers identified and fixed
several stability bugs in the browser engine used in Firefox and other
Mozilla-based products. Some of these crashes showed evidence of
memory corruption under certain circumstances and we presume that with
enough effort at least some of these could be exploited to run
arbitrary code.

MFSA 2009-07 / CVE-2009-0772 / CVE-2009-0774: Mozilla developers
identified and fixed several stability bugs in the browser engine used
in Firefox and other Mozilla-based products. Some of these crashes
showed evidence of memory corruption under certain circumstances and
we presume that with enough effort at least some of these could be
exploited to run arbitrary code.

MFSA 2009-09 / CVE-2009-0776: Mozilla security researcher Georgi
Guninski reported that a website could use nsIRDFService and a
cross-domain redirect to steal arbitrary XML data from another domain,
a violation of the same-origin policy. This vulnerability could be
used by a malicious website to steal private data from users
authenticated to the redirected website.

MFSA 2009-10 / CVE-2009-0040: Google security researcher Tavis Ormandy
reported several memory safety hazards to the libpng project, an
external library used by Mozilla to render PNG images. These
vulnerabilities could be used by a malicious website to crash a
victim's browser and potentially execute arbitrary code on their
computer. libpng was upgraded to version 1.2.35 which containis fixes
for these flaws.

MFSA 2009-12 / CVE-2009-1169: Security researcher Guido Landi
discovered that a XSL stylesheet could be used to crash the browser
during a XSL transformation. An attacker could potentially use this
crash to run arbitrary code on a victim's computer. This vulnerability
was also previously reported as a stability problem by Ubuntu
community member, Andre. Ubuntu community member Michael Rooney
reported Andre's findings to Mozilla, and Mozilla community member
Martin helped reduce Andre's original testcase and contributed a patch
to fix the vulnerability."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/21");
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

if ( rpm_check(release:"SUSE10.3", reference:"MozillaFirefox-2.0.0.21post-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"MozillaFirefox-translations-2.0.0.21post-0.1") ) flag++;

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

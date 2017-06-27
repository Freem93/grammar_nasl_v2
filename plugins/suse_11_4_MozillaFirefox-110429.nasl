#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-4457.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75944);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2011-0068", "CVE-2011-0070", "CVE-2011-0079", "CVE-2011-0081", "CVE-2011-1202");

  script_name(english:"openSUSE Security Update : MozillaFirefox (MozillaFirefox-4457)");
  script_summary(english:"Check for the MozillaFirefox-4457 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to the 4.0.1 security release.

MFSA 2011-12: Mozilla developers identified and fixed several memory
safety bugs in the browser engine used in Firefox and other
Mozilla-based products. Some of these bugs showed evidence of memory
corruption under certain circumstances, and we presume that with
enough effort at least some of these could be exploited to run
arbitrary code. Credits

Mozilla developers Boris Zbarsky, Gary Kwong, Jesse Ruderman, Michael
Wu, Nils, Scoobidiver, and Ted Mielczarek reported memory safety
issues which affected Firefox 4. (CVE-2011-0079)

Mozilla developer Scoobidiver reported a memory safety issue which
affected Firefox 4 and Firefox 3.6 (CVE-2011-0081)

Ian Beer reported a crash that affected Firefox 4, Firefox 3.6 and
Firefox 3.5. (CVE-2011-0070)

MFSA 2011-17 / CVE-2011-0068: Two crashes that could potentially be
exploited to run malicious code were found in the WebGL feature and
fixed in Firefox 4.0.1. In addition the WebGLES libraries could
potentially be used to bypass a security feature of recent Windows
versions. The WebGL feature was introduced in Firefox 4; older
versions are not affected by these issues.

Nils reported that the WebGLES libraries in the Windows version of
Firefox were compiled without ASLR protection. An attacker who found
an exploitable memory corruption flaw could then use these libraries
to bypass ASLR on Windows Vista and Windows 7, making the flaw as
exploitable on those platforms as it would be on Windows XP or other
platforms.

Mozilla researcher Christoph Diehl reported a potentially exploitable
buffer overflow in the WebGLES library

Yuri Ko reported a potentially exploitable overwrite in the WebGLES
library to the Chrome Secuity Team. We thank them for coordinating
with us on this fix.

MFSA 2011-18 / CVE-2011-1202: Chris Evans of the Chrome Security Team
reported that the XSLT generate-id() function returned a string that
revealed a specific valid address of an object on the memory heap. It
is possible that in some cases this address would be valuable
information that could be used by an attacker while exploiting a
different memory corruption but, in order to make an exploit more
reliable or work around mitigation features in the browser or
operating system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=689281"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js20-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js20-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js20-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner20-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner20-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner20-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner20-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner20-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner20-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner20-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner20-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner20-gnome-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner20-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner20-gnome-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner20-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner20-translations-common-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner20-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner20-translations-other-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/29");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-4.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-branding-upstream-4.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-debuginfo-4.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-debugsource-4.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-devel-4.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-translations-common-4.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-translations-other-4.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-js20-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-js20-debuginfo-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner20-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner20-buildsymbols-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner20-debuginfo-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner20-debugsource-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner20-devel-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner20-devel-debuginfo-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner20-gnome-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner20-gnome-debuginfo-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner20-translations-common-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner20-translations-other-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-js20-32bit-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-js20-debuginfo-32bit-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner20-32bit-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner20-debuginfo-32bit-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner20-gnome-32bit-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner20-gnome-debuginfo-32bit-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner20-translations-common-32bit-2.0.1-0.2.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner20-translations-other-32bit-2.0.1-0.2.2") ) flag++;

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

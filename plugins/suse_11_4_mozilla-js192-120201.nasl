#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update mozilla-js192-5749.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75961);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/01 13:32:21 $");

  script_cve_id("CVE-2011-3659", "CVE-2011-3670", "CVE-2012-0442", "CVE-2012-0444", "CVE-2012-0449");

  script_name(english:"openSUSE Security Update : mozilla-js192 (mozilla-js192-5749)");
  script_summary(english:"Check for the mozilla-js192-5749 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"mozilla xulrunner was updated to 1.9.2.26 security update, fixing
security issues and bugs. Following security bugs were fixed :

MFSA 2012-01: Mozilla developers identified and fixed several memory
safety bugs in the browser engine used in Firefox and other
Mozilla-based products. Some of these bugs showed evidence of memory
corruption under certain circumstances, and we presume that with
enough effort at least some of these could be exploited to run
arbitrary code.

In general these flaws cannot be exploited through email in the
Thunderbird and SeaMonkey products because scripting is disabled, but
are potentially a risk in browser or browser-like contexts in those
products. References

CVE-2012-0442: Jesse Ruderman and Bob Clary reported memory safety
problems that were fixed in both Firefox 10 and Firefox 3.6.26.

MFSA 2012-02/CVE-2011-3670: For historical reasons Firefox has been
generous in its interpretation of web addresses containing square
brackets around the host. If this host was not a valid IPv6 literal
address, Firefox attempted to interpret the host as a regular domain
name. Gregory Fleischer reported that requests made using IPv6 syntax
using XMLHttpRequest objects through a proxy may generate errors
depending on proxy configuration for IPv6. The resulting error
messages from the proxy may disclose sensitive data because
Same-Origin Policy (SOP) will allow the XMLHttpRequest object to read
these error messages, allowing user privacy to be eroded. Firefox now
enforces RFC 3986 IPv6 literal syntax and that may break links written
using the non-standard Firefox-only forms that were previously
accepted.

This was fixed previously for Firefox 7.0, Thunderbird 7.0, and
SeaMonkey 2.4 but only fixed in Firefox 3.6.26 and Thunderbird 3.1.18
during 2012.

MFSA 2012-04/CVE-2011-3659: Security researcher regenrecht reported
via TippingPoint's Zero Day Initiative that removed child nodes of
nsDOMAttribute can be accessed under certain circumstances because of
a premature notification of AttributeChildRemoved. This use-after-free
of the child nodes could possibly allow for for remote code execution.

MFSA 2012-07/CVE-2012-0444: Security researcher regenrecht reported
via TippingPoint's Zero Day Initiative the possibility of memory
corruption during the decoding of Ogg Vorbis files. This can cause a
crash during decoding and has the potential for remote code execution.

MFSA 2012-08/CVE-2012-0449: Security researchers Nicolas Gregoire and
Aki Helin independently reported that when processing a malformed
embedded XSLT stylesheet, Firefox can crash due to a memory
corruption. While there is no evidence that this is directly
exploitable, there is a possibility of remote code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744275"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla-js192 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 8/9 AttributeChildRemoved() Use-After-Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-common-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-other-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.4", reference:"mozilla-js192-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-js192-debuginfo-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-buildsymbols-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-debuginfo-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-debugsource-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-devel-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-devel-debuginfo-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-gnome-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-gnome-debuginfo-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-translations-common-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-translations-other-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-js192-32bit-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-js192-debuginfo-32bit-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-debuginfo-32bit-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-debuginfo-32bit-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-common-32bit-1.9.2.26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-other-32bit-1.9.2.26-0.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-xulrunner192");
}

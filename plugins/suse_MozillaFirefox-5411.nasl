#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-5411.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(33499);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2806", "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2810", "CVE-2008-2811");

  script_name(english:"openSUSE 10 Security Update : MozillaFirefox (MozillaFirefox-5411)");
  script_summary(english:"Check for the MozillaFirefox-5411 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to version 2.0.0.15, fixing various bugs
including following security bugs :

CVE-2008-2798 CVE-2008-2799 MFSA-2008-21: Mozilla developers
identified and fixed several stability bugs in the browser engine used
in Firefox and other Mozilla-based products. Some of these crashes
showed evidence of memory corruption under certain circumstances and
we presume that with enough effort at least some of these could be
exploited to run arbitrary code.

CVE-2008-2800 MFSA-2008-22: Mozilla contributor moz_bug_r_a4 submitted
a set of vulnerabilities which allow scripts from one document to be
executed in the context of a different document. These vulnerabilities
could be used by an attacker to violate the same-origin policy and
perform an XSS attack.

CVE-2008-2801 MFSA-2008-23: Security researcher Collin Jackson
reported a series of vulnerabilities which allow JavaScript to be
injected into signed JARs and executed under the context of the JAR's
signer. This could allow an attacker to run JavaScript in a victim's
browser with the privileges of a different website, provided the
attacker possesses a JAR signed by the other website.

CVE-2008-2802 MFSA-2008-24: Mozilla contributor moz_bug_r_a4 reported
a vulnerability that allowed non-priviliged XUL documents to load
chrome scripts from the fastload file. This could allow an attacker to
run arbitrary JavaScript code with chrome privileges.

CVE-2008-2803 MFSA-2008-25: Mozilla contributor moz_bug_r_a4 reported
a vulnerability which allows arbitrary JavaScript to be executed with
chrome privileges. The privilege escalation was possible because
JavaScript loaded via mozIJSSubScriptLoader.loadSubScript() was not
using XPCNativeWrappers when accessing content. This could allow an
attacker to overwrite trusted objects with arbitrary code which would
be executed with chrome privileges when the trusted objects were
called by the browser.

CVE-2008-2805 MFSA-2008-27: Opera developer Claudio Santambrogio
reported a vulnerability which allows malicious content to force the
browser into uploading local files to the remote server. This could be
used by an attacker to steal arbitrary files from a victim's computer.

CVE-2008-2806 MFSA-2008-28: Security researcher Gregory Fleischer
reported a vulnerability in the way Mozilla indicates the origin of a
document to the Java plugin. This vulnerability could allow a
malicious Java applet to bypass the same-origin policy and create
arbitrary socket connections to other domains.

CVE-2008-2807 MFSA-2008-29: Mozilla developer Daniel Glazman
demonstrated that an improperly encoded .properties file in an add-on
can result in uninitialized memory being used. This could potentially
result in small chunks of data from other programs being exposed in
the browser.

CVE-2008-2808 MFSA-2008-30: Mozilla contributor Masahiro Yamada
reported that file URLs in directory listings were not being HTML
escaped properly when the filenames contained particular characters.
This resulted in files from directory listings being opened in
unintended ways or files not being able to be opened by the browser
altogether.

CVE-2008-2809 MFSA-2008-31: Mozilla developer John G. Myers reported a
weakness in the trust model used by Mozilla regarding alternate names
on self-signed certificates. A user could be prompted to accept a
self-signed certificate from a website which includes alt-name
entries. If the user accepted the certificate, they would also extend
trust to any alternate domains listed in the certificate, despite not
being prompted about the additional domains. This technique could be
used by an attacker to impersonate another server.

CVE-2008-2810 MFSA-2008-32: Mozilla community member Geoff reported a
vulnerability in the way Mozilla opens URL files sent directly to the
browser. He demonstrated that such files were opened with local file
privileges, giving the remote content access to read from the local
filesystem. If a user opened a bookmark to a malicious page in this
manner, the page could potentially read from other local files on the
user's computer.

CVE-2008-2811 MFSA 2008-33: Security research firm Astabis, via the
iSIGHT Partners GVP Program, reported a vulnerability in Mozilla's
block reflow code. This vulnerablitity could be used by an attacker to
crash the browser and run arbitrary code on the victim's computer."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 79, 200, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"MozillaFirefox-2.0.0.15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"MozillaFirefox-translations-2.0.0.15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"MozillaFirefox-2.0.0.15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"MozillaFirefox-translations-2.0.0.15-0.1") ) flag++;

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

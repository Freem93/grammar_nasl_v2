#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(33498);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2806", "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2810", "CVE-2008-2811");

  script_name(english:"SuSE 10 Security Update : MozillaFirefox (ZYPP Patch Number 5405)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to version 2.0.0.15, fixing various bugs
including following security bugs :

  - Mozilla developers identified and fixed several
    stability bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these crashes
    showed evidence of memory corruption under certain
    circumstances and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (CVE-2008-2798 / CVE-2008-2799 / MFSA 2008-21)

  - Mozilla contributor moz_bug_r_a4 submitted a set of
    vulnerabilities which allow scripts from one document to
    be executed in the context of a different document.
    These vulnerabilities could be used by an attacker to
    violate the same-origin policy and perform an XSS
    attack. (CVE-2008-2800 / MFSA 2008-22)

  - Security researcher Collin Jackson reported a series of
    vulnerabilities which allow JavaScript to be injected
    into signed JARs and executed under the context of the
    JAR's signer. This could allow an attacker to run
    JavaScript in a victim's browser with the privileges of
    a different website, provided the attacker possesses a
    JAR signed by the other website. (CVE-2008-2801 / MFSA
    2008-23)

  - Mozilla contributor moz_bug_r_a4 reported a
    vulnerability that allowed non-priviliged XUL documents
    to load chrome scripts from the fastload file. This
    could allow an attacker to run arbitrary JavaScript code
    with chrome privileges. (CVE-2008-2802 / MFSA 2008-24)

  - Mozilla contributor moz_bug_r_a4 reported a
    vulnerability which allows arbitrary JavaScript to be
    executed with chrome privileges. The privilege
    escalation was possible because JavaScript loaded via
    mozIJSSubScriptLoader.loadSubScript() was not using
    XPCNativeWrappers when accessing content. This could
    allow an attacker to overwrite trusted objects with
    arbitrary code which would be executed with chrome
    privileges when the trusted objects were called by the
    browser. (CVE-2008-2803 / MFSA 2008-25)

  - Opera developer Claudio Santambrogio reported a
    vulnerability which allows malicious content to force
    the browser into uploading local files to the remote
    server. This could be used by an attacker to steal
    arbitrary files from a victim's computer. (CVE-2008-2805
    / MFSA 2008-27)

  - Security researcher Gregory Fleischer reported a
    vulnerability in the way Mozilla indicates the origin of
    a document to the Java plugin. This vulnerability could
    allow a malicious Java applet to bypass the same-origin
    policy and create arbitrary socket connections to other
    domains. (CVE-2008-2806 / MFSA 2008-28)

  - Mozilla developer Daniel Glazman demonstrated that an
    improperly encoded .properties file in an add-on can
    result in uninitialized memory being used. This could
    potentially result in small chunks of data from other
    programs being exposed in the browser. (CVE-2008-2807 /
    MFSA 2008-29)

  - Mozilla contributor Masahiro Yamada reported that file
    URLs in directory listings were not being HTML escaped
    properly when the filenames contained particular
    characters. This resulted in files from directory
    listings being opened in unintended ways or files not
    being able to be opened by the browser altogether.
    (CVE-2008-2808 / MFSA 2008-30)

  - Mozilla developer John G. Myers reported a weakness in
    the trust model used by Mozilla regarding alternate
    names on self-signed certificates. A user could be
    prompted to accept a self-signed certificate from a
    website which includes alt-name entries. If the user
    accepted the certificate, they would also extend trust
    to any alternate domains listed in the certificate,
    despite not being prompted about the additional domains.
    This technique could be used by an attacker to
    impersonate another server. (CVE-2008-2809 / MFSA
    2008-31)

  - Mozilla community member Geoff reported a vulnerability
    in the way Mozilla opens URL files sent directly to the
    browser. He demonstrated that such files were opened
    with local file privileges, giving the remote content
    access to read from the local filesystem. If a user
    opened a bookmark to a malicious page in this manner,
    the page could potentially read from other local files
    on the user's computer. (CVE-2008-2810 / MFSA 2008-32)

  - Security research firm Astabis, via the iSIGHT Partners
    GVP Program, reported a vulnerability in Mozilla's block
    reflow code. This vulnerablitity could be used by an
    attacker to crash the browser and run arbitrary code on
    the victim's computer. (CVE-2008-2811 / MFSA 2008-33)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-21.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-22.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-23.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-24.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-25.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-27.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-28.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-29.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-30.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-31.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-32.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-33.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2798.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2799.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2800.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2801.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2802.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2803.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2805.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2806.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2807.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2808.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2809.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2810.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2811.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5405.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 79, 200, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:1, reference:"MozillaFirefox-2.0.0.15-0.2.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"MozillaFirefox-translations-2.0.0.15-0.2.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"MozillaFirefox-2.0.0.15-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"MozillaFirefox-translations-2.0.0.15-0.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"MozillaFirefox-2.0.0.15-0.2.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"MozillaFirefox-translations-2.0.0.15-0.2.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"MozillaFirefox-2.0.0.15-0.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"MozillaFirefox-translations-2.0.0.15-0.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");

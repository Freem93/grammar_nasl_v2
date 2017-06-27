#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(49900);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/22 20:42:28 $");

  script_cve_id("CVE-2009-1571", "CVE-2009-3988", "CVE-2010-0159", "CVE-2010-0160", "CVE-2010-0162");

  script_name(english:"SuSE 10 Security Update : Mozilla XULRunner (ZYPP Patch Number 6866)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla XUL Runner engine 1.9.0 was upgraded to version 1.9.0.8,
fixing various bugs and security issues.

The following security issues have been fixed :

  - Mozilla developers identified and fixed several
    stability bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these crashes
    showed evidence of memory corruption under certain
    circumstances and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2010-01 / CVE-2010-0159)

  - Security researcher Orlando Barrera II reported via
    TippingPoint's Zero Day Initiative that Mozilla's
    implementation of Web Workers contained an error in its
    handling of array data types when processing posted
    messages. This error could be used by an attacker to
    corrupt heap memory and crash the browser, potentially
    running arbitrary code on a victim's computer. (MFSA
    2010-02 / CVE-2010-0160)

  - Security researcher Alin Rad Pop of Secunia Research
    reported that the HTML parser incorrectly freed used
    memory when insufficient space was available to process
    remaining input. Under such circumstances, memory
    occupied by in-use objects was freed and could later be
    filled with attacker-controlled text. These conditions
    could result in the execution or arbitrary code if
    methods on the freed objects were subsequently called.
    (MFSA 2010-03 / CVE-2009-1571)

  - Security researcher Hidetake Jo of Microsoft
    Vulnerability Research reported that the properties set
    on an object passed to showModalDialog were readable by
    the document contained in the dialog, even when the
    document was from a different domain. This is a
    violation of the same-origin policy and could result in
    a website running untrusted JavaScript if it assumed the
    dialogArguments could not be initialized by another
    site. (MFSA 2010-04 / CVE-2009-3988)

An anonymous security researcher, via TippingPoint's Zero Day
Initiative, also independently reported this issue to Mozilla.

  - Mozilla security researcher Georgi Guninski reported
    that when a SVG document which is served with
    Content-Type: application/octet-stream is embedded into
    another document via an tag with type='image/svg+xml',
    the Content-Type is ignored and the SVG document is
    processed normally. A website which allows arbitrary
    binary data to be uploaded but which relies on
    Content-Type: application/octet-stream to prevent script
    execution could have such protection bypassed. An
    attacker could upload a SVG document containing
    JavaScript as a binary file to a website, embed the SVG
    document into a malicous page on another site, and gain
    access to the script environment from the SVG-serving
    site, bypassing the same-origin policy. (MFSA 2010-05 /
    CVE-2010-0162)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-01.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-02.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-03.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-04.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-05.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1571.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3988.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0159.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0160.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0162.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6866.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 94, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:3, reference:"mozilla-xulrunner190-1.9.0.18-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"mozilla-xulrunner190-gnomevfs-1.9.0.18-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"mozilla-xulrunner190-translations-1.9.0.18-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.18-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.18-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.18-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner190-1.9.0.18-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner190-gnomevfs-1.9.0.18-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner190-translations-1.9.0.18-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.18-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.18-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.18-0.4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");

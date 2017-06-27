#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(58525);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2012/06/14 20:08:54 $");

  script_cve_id("CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0457", "CVE-2012-0458", "CVE-2012-0461", "CVE-2012-0462", "CVE-2012-0463", "CVE-2012-0464");

  script_name(english:"SuSE 10 Security Update : Mozilla Firefox (ZYPP Patch Number 8029)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to 3.6.28 to fix various bugs and security
issues.

The following security issues have been fixed :

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2012-19)

    In general these flaws cannot be exploited through email
    in the Thunderbird and SeaMonkey products because
    scripting is disabled, but are potentially a risk in
    browser or browser-like contexts in those products.
    References

    Bob Clary reported two bugs that causes crashes that
    affected Firefox 3.6, Firefox ESR, and Firefox 10.
    (CVE-2012-0461)

    Christian Holler, Jesse Ruderman, Nils, Michael
    Bebenita, Dindog, and David Anderson reported memory
    safety problems and crashes that affect Firefox ESR and
    Firefox 10. (CVE-2012-0462)

    Jeff Walden reported a memory safety problem in the
    array.join function. This bug was independently reported
    by Vincenzo Iozzo via TippingPoint's Zero Day Initiative
    Pwn2Own contest. (CVE-2012-0464)

    Masayuki Nakano reported a memory safety problem that
    affected Mobile Firefox 10. (CVE-2012-0463)

  - Security researcher Mariusz Mlynski reported that an
    attacker able to convince a potential victim to set a
    new home page by dragging a link to the 'home' button
    can set that user's home page to a javascript: URL. Once
    this is done the attacker's page can cause repeated
    crashes of the browser, eventually getting the script
    URL loaded in the privileged about:sessionrestore
    context. (MFSA 2012-16 / CVE-2012-0458)

  - Security researcher Atte Kettunen from OUSPG found two
    issues with Firefox's handling of SVG using the Address
    Sanitizer tool. The first issue, critically rated, is a
    use-after-free in SVG animation that could potentially
    lead to arbitrary code execution. The second issue is
    rated moderate and is an out of bounds read in SVG
    Filters. This could potentially incorporate data from
    the user's memory, making it accessible to the page
    content. (MFSA 2012-14 / CVE-2012-0457 / CVE-2012-0456)

  - Firefox prevents the dropping of javascript: links onto
    a frame to prevent malicious sites from tricking users
    into performing a cross-site scripting (XSS) attacks on
    themselves. Security researcher Soroush Dalili reported
    a way to bypass this protection. (MFSA 2012-13 /
    CVE-2012-0455)

The full overview can be found on Mozillas security page at:
http://www.mozilla.org/security/announce/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-14.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-19.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0455.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0456.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0457.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0458.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0461.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0462.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0463.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0464.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8029.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, reference:"MozillaFirefox-3.6.28-0.5.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"MozillaFirefox-translations-3.6.28-0.5.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nspr-4.9.0-0.6.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nspr-devel-4.9.0-0.6.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nss-3.13.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nss-devel-3.13.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nss-tools-3.13.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-xulrunner192-1.9.2.28-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-xulrunner192-gnome-1.9.2.28-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-xulrunner192-translations-1.9.2.28-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.0-0.6.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.28-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.28-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"mozilla-xulrunner192-translations-32bit-1.9.2.28-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"MozillaFirefox-3.6.28-0.5.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"MozillaFirefox-translations-3.6.28-0.5.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nspr-4.9.0-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nspr-devel-4.9.0-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nss-3.13.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nss-devel-3.13.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nss-tools-3.13.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-xulrunner192-1.9.2.28-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-xulrunner192-gnome-1.9.2.28-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-xulrunner192-translations-1.9.2.28-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.0-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.28-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.28-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"mozilla-xulrunner192-translations-32bit-1.9.2.28-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");

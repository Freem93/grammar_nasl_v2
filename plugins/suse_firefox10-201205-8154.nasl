#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59354);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/30 13:08:31 $");

  script_cve_id("CVE-2011-1187", "CVE-2011-3062", "CVE-2012-0467", "CVE-2012-0468", "CVE-2012-0469", "CVE-2012-0470", "CVE-2012-0471", "CVE-2012-0472", "CVE-2012-0473", "CVE-2012-0474", "CVE-2012-0475", "CVE-2012-0477", "CVE-2012-0478", "CVE-2012-0479");

  script_name(english:"SuSE 10 Security Update : MozillaFirefox (ZYPP Patch Number 8154)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox was updated to the 10.0.4 ESR release to fix various
bugs and security issues.

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2012-20)

    In general these flaws cannot be exploited through email
    in the Thunderbird and SeaMonkey products because
    scripting is disabled, but are potentially a risk in
    browser or browser-like contexts in those products.

o

Christian Holler a reported memory safety and security
problem affecting Firefox 11. (CVE-2012-0468)

o

Bob Clary, Christian Holler, Brian Hackett, Bobby Holley,
Gary Kwong, Hilary Hall, Honza Bambas, Jesse Ruderman,
Julian Seward, and Olli Pettay reported memory safety
problems and crashes that affect Firefox ESR and Firefox 11.
(CVE-2012-0467)

  - Using the Address Sanitizer tool, security researcher
    Aki Helin from OUSPG found that IDBKeyRange of indexedDB
    remains in the XPConnect hashtable instead of being
    unlinked before being destroyed. When it is destroyed,
    this causes a use-after-free, which is potentially
    exploitable. (MFSA 2012-22 / CVE-2012-0469)

  - Using the Address Sanitizer tool, security researcher
    Atte Kettunen from OUSPG found a heap corruption in
    gfxImageSurface which allows for invalid frees and
    possible remote code execution. This happens due to
    float error, resulting from graphics values being passed
    through different number systems. (MFSA 2012-23 /
    CVE-2012-0470)

  - Anne van Kesteren of Opera Software found a multi-octet
    encoding issue where certain octets will destroy the
    following octets in the processing of some multibyte
    character sets. This can leave users vulnerable to
    cross-site scripting (XSS) attacks on maliciously
    crafted web pages. (MFSA 2012-24 / CVE-2012-0471)

  - Security research firm iDefense reported that researcher
    wushi of team509 discovered a memory corruption on
    Windows Vista and Windows 7 systems with hardware
    acceleration disabled or using incompatible video
    drivers. This is created by using cairo-dwrite to
    attempt to render fonts on an unsupported code path.
    This corruption causes a potentially exploitable crash
    on affected systems. (MFSA 2012-25 / CVE-2012-0472)

  - Mozilla community member Matias Juntunen discovered an
    error in WebGLBuffer where FindMaxElementInSubArray
    receives wrong template arguments from
    FindMaxUshortElement. This bug causes maximum index to
    be computed incorrectly within WebGL.drawElements,
    allowing the reading of illegal video memory. (MFSA
    2012-26 / CVE-2012-0473)

  - Security researchers Jordi Chancel and Eddy Bordi
    reported that they could short-circuit page loads to
    show the address of a different site than what is loaded
    in the window in the addressbar. Security researcher
    Chris McGowen independently reported the same flaw, and
    further demonstrated that this could lead to loading
    scripts from the attacker's site, leaving users
    vulnerable to cross-site scripting (XSS) attacks. (MFSA
    2012-27 / CVE-2012-0474)

  - Security researcher Simone Fabiano reported that if a
    cross-site XHR or WebSocket is opened on a web server on
    a non-standard port for web traffic while using an IPv6
    address, the browser will send an ambiguous origin
    headers if the IPv6 address contains at least 2
    consecutive 16-bit fields of zeroes. If there is an
    origin access control list that uses IPv6 literals, this
    issue could be used to bypass these access controls on
    the server. (MFSA 2012-28 / CVE-2012-0475)

  - Security researcher Masato Kinugawa found that during
    the decoding of ISO-2022-KR and ISO-2022-CN character
    sets, characters near 1024 bytes are treated
    incorrectly, either doubling or deleting bytes. On
    certain pages it might be possible for an attacker to
    pad the output of the page such that these errors fall
    in the right place to affect the structure of the page,
    allowing for cross-site script (XSS) injection. (MFSA
    2012-29 / CVE-2012-0477)

  - Mozilla community member Ms2ger found an image rendering
    issue with WebGL when texImage2D uses use
    JSVAL_TO_OBJECT on arbitrary objects. This can lead to a
    crash on a maliciously crafted web page. While there is
    no evidence that this is directly exploitable, there is
    a possibility of remote code execution. (MFSA 2012-30 /
    CVE-2012-0478)

  - Mateusz Jurczyk of the Google Security Team discovered
    an off-by-one error in the OpenType Sanitizer using the
    Address Sanitizer tool. This can lead to an
    out-of-bounds read and execution of an uninitialized
    function pointer during parsing and possible remote code
    execution. (MFSA 2012-31 / CVE-2011-3062)

  - Security researcher Daniel Divricean reported that a
    defect in the error handling of JavaScript errors can
    leak the file names and location of JavaScript files on
    a server, leading to inadvertent information disclosure
    and a vector for further attacks. (MFSA 2012-32 /
    CVE-2011-1187)

  - Security researcher Jeroen van der Gun reported that if
    RSS or Atom XML invalid content is loaded over HTTPS,
    the addressbar updates to display the new location of
    the loaded resource, including SSL indicators, while the
    main window still displays the previously loaded
    content. This allows for phishing attacks where a
    malicious page can spoof the identify of another
    seemingly secure site. (MFSA 2012-33 / CVE-2012-0479)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-20.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-22.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-23.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-24.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-25.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-26.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-27.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-28.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-29.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-30.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-31.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1187.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3062.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0467.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0468.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0469.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0470.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0471.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0472.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0473.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0474.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0475.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0477.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0478.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0479.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8154.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, reference:"MozillaFirefox-10.0.4-0.7.6")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"MozillaFirefox-branding-SLED-7-0.8.12")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"MozillaFirefox-translations-10.0.4-0.7.6")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"beagle-0.2.18-78.13.1.102")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"beagle-evolution-0.2.18-78.13.1.102")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"beagle-firefox-0.2.18-78.13.1.102")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"beagle-gui-0.2.18-78.13.1.102")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"firefox3-gtk2-2.10.6-0.10.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mhtml-firefox-0.5-1.11.5")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nss-3.13.4-0.5.5")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nss-devel-3.13.4-0.5.5")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nss-tools-3.13.4-0.5.5")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"firefox3-gtk2-32bit-2.10.6-0.10.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.4-0.5.5")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"MozillaFirefox-10.0.4-0.7.6")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"MozillaFirefox-branding-SLED-7-0.8.12")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"MozillaFirefox-translations-10.0.4-0.7.6")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"firefox3-gtk2-2.10.6-0.10.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nss-3.13.4-0.5.5")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nss-devel-3.13.4-0.5.5")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nss-tools-3.13.4-0.5.5")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"firefox3-gtk2-32bit-2.10.6-0.10.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.4-0.5.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");

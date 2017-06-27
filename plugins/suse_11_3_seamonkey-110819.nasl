#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update seamonkey-5024.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75739);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/21 14:15:34 $");

  script_cve_id("CVE-2011-0084", "CVE-2011-2985", "CVE-2011-2986", "CVE-2011-2987", "CVE-2011-2988", "CVE-2011-2989", "CVE-2011-2990", "CVE-2011-2991", "CVE-2011-2992", "CVE-2011-2993");
  script_osvdb_id(74581, 74588, 74589, 74590, 74591, 74592, 74593, 74594, 74595, 74596);

  script_name(english:"openSUSE Security Update : seamonkey (openSUSE-SU-2011:0957-1)");
  script_summary(english:"Check for the seamonkey-5024 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla SeaMonkey suite was updated to version 2.3.

The update fixes bugs and security issues. Following security issues
were fixed:
http://www.mozilla.org/security/announce/2011/mfsa2011-33.html Mozilla
Foundation Security Advisory 2011-33 (MFSA 2011-33) Mozilla Foundation
Security Advisory 2011-33

  - Miscellaneous memory safety hazards (rv:4.0) Mozilla
    identified and fixed several memory safety bugs in the
    browser engine used in SeaMonkey 2.2 and other
    Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code.

    Aral Yaman reported a WebGL crash which affected
    SeaMonkey 2.2. (CVE-2011-2989)

    Vivekanand Bolajwar reported a JavaScript crash which
    affected SeaMonkey 2.2. (CVE-2011-2991)

    Bert Hubert and Theo Snelleman of Fox-IT reported a
    crash in the Ogg reader which affected SeaMonkey 2.2.
    (CVE-2011-2992)

    Mozilla developers and community members Robert Kaiser,
    Jesse Ruderman, moz_bug_r_a4, Mardeg, Gary Kwong,
    Christoph Diehl, Martijn Wargers, Travis Emmitt, Bob
    Clary and Jonathan Watt reported memory safety issues
    which affected SeaMonkey 2.2. (CVE-2011-2985)

  - Unsigned scripts can call script inside signed JAR

    Rafael Gieschke reported that unsigned JavaScript could
    call into script inside a signed JAR thereby inheriting
    the identity of the site that signed the JAR as well as
    any permissions that a user had granted the signed JAR.
    (CVE-2011-2993)

  - String crash using WebGL shaders

    Michael Jordon of Context IS reported that an overly
    long shader program could cause a buffer overrun and
    crash in a string class used to store the shader source
    code. (CVE-2011-2988)

  - Heap overflow in ANGLE library

    Michael Jordon of Context IS reported a potentially
    exploitable heap overflow in the ANGLE library used by
    Mozilla's WebGL implementation. (CVE-2011-2987)

  - Crash in SVGTextElement.getCharNumAtPosition()

    Security researcher regenrecht reported via
    TippingPoint's Zero Day Initiative that a SVG text
    manipulation routine contained a dangling pointer
    vulnerability. (CVE-2011-0084)

  - Credential leakage using Content Security Policy reports

    Mike Cardwell reported that Content Security Policy
    violation reports failed to strip out proxy
    authorization credentials from the list of request
    headers. Daniel Veditz reported that redirecting to a
    website with Content Security Policy resulted in the
    incorrect resolution of hosts in the constructed policy.
    (CVE-2011-2990)

  - Cross-origin data theft using canvas and Windows D2D

    nasalislarvatus3000 reported that when using Windows D2D
    hardware acceleration, image data from one domain could
    be inserted into a canvas and read by a different
    domain. (CVE-2011-2986)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-08/msg00039.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-33.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712224"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-venkman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/19");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"seamonkey-2.3-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"seamonkey-dom-inspector-2.3-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"seamonkey-irc-2.3-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"seamonkey-translations-common-2.3-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"seamonkey-translations-other-2.3-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"seamonkey-venkman-2.3-2.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey");
}

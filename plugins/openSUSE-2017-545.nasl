#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-545.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(100020);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/22 13:36:33 $");

  script_cve_id("CVE-2017-5398", "CVE-2017-5399", "CVE-2017-5400", "CVE-2017-5401", "CVE-2017-5402", "CVE-2017-5403", "CVE-2017-5404", "CVE-2017-5405", "CVE-2017-5406", "CVE-2017-5407", "CVE-2017-5408", "CVE-2017-5410", "CVE-2017-5412", "CVE-2017-5413", "CVE-2017-5414", "CVE-2017-5416", "CVE-2017-5418", "CVE-2017-5419", "CVE-2017-5421", "CVE-2017-5422", "CVE-2017-5426", "CVE-2017-5429", "CVE-2017-5430", "CVE-2017-5432", "CVE-2017-5433", "CVE-2017-5434", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5437", "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441", "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5449", "CVE-2017-5451", "CVE-2017-5454", "CVE-2017-5459", "CVE-2017-5460", "CVE-2017-5461", "CVE-2017-5462", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5466", "CVE-2017-5467", "CVE-2017-5469");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2017-545)");
  script_summary(english:"Check for the openSUSE-2017-545 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to MozillaThunderbird 51.1.0 fixes security issues and
bugs.

In general, these flaws cannot be exploited through email because
scripting is disabled when reading mail, but are potentially risks in
browser or browser-like contexts.

The following vulnerabilities were fixed: boo#1035082, MFSA 2017-13,
boo#1028391, MFSA 2017-09)

  - CVE-2017-5443: Out-of-bounds write during BinHex
    decoding

  - CVE-2017-5429: Memory safety bugs fixed in Firefox 53,
    Firefox ESR 45.9, and Firefox ESR 52.1

  - CVE-2017-5464: Memory corruption with accessibility and
    DOM manipulation

  - CVE-2017-5465: Out-of-bounds read in ConvolvePixel

  - CVE-2017-5466: Origin confusion when reloading isolated
    data:text/html URL

  - CVE-2017-5467: Memory corruption when drawing Skia
    content

  - CVE-2017-5460: Use-after-free in frame selection

  - CVE-2017-5449: Crash during bidirectional unicode
    manipulation with animation

  - CVE-2017-5446: Out-of-bounds read when HTTP/2 DATA
    frames are sent with incorrect data

  - CVE-2017-5447: Out-of-bounds read during glyph
    processing

  - CVE-2017-5444: Buffer overflow while parsing
    application/http-index-format content

  - CVE-2017-5445: Uninitialized values used while parsing
    application/http-index-format content

  - CVE-2017-5442: Use-after-free during style changes

  - CVE-2017-5469: Potential Buffer overflow in
    flex-generated code

  - CVE-2017-5440: Use-after-free in txExecutionState
    destructor during XSLT processing

  - CVE-2017-5441: Use-after-free with selection during
    scroll events

  - CVE-2017-5439: Use-after-free in nsTArray Length()
    during XSLT processing

  - CVE-2017-5438: Use-after-free in nsAutoPtr during XSLT
    processing

  - CVE-2017-5437: Vulnerabilities in Libevent library

  - CVE-2017-5436: Out-of-bounds write with malicious font
    in Graphite 2

  - CVE-2017-5435: Use-after-free during transaction
    processing in the editor

  - CVE-2017-5434: Use-after-free during focus handling

  - CVE-2017-5433: Use-after-free in SMIL animation
    functions

  - CVE-2017-5432: Use-after-free in text input selection

  - CVE-2017-5430: Memory safety bugs fixed in Firefox 53
    and Firefox ESR 52.1

  - CVE-2017-5459: Buffer overflow in WebGL

  - CVE-2017-5454; Sandbox escape allowing file system read
    access through file picker

  - CVE-2017-5451: Addressbar spoofing with onblur event

  - CVE-2017-5400: asm.js JIT-spray bypass of ASLR and DEP

  - CVE-2017-5401: Memory Corruption when handling
    ErrorResult

  - CVE-2017-5402: Use-after-free working with events in
    FontFace objects

  - CVE-2017-5403: Use-after-free using addRange to add
    range to an incorrect root object

  - CVE-2017-5404: Use-after-free working with ranges in
    selections

  - CVE-2017-5406: Segmentation fault in Skia with canvas
    operations 

  - CVE-2017-5407: Pixel and history stealing via
    floating-point timing side channel with SVG filters

  - CVE-2017-5410: Memory corruption during JavaScript
    garbage collection incremental sweeping

  - CVE-2017-5408: Cross-origin reading of video captions in
    violation of CORS

  - CVE-2017-5412: Buffer overflow read in SVG filters

  - CVE-2017-5413: Segmentation fault during bidirectional
    operations

  - CVE-2017-5414: File picker can choose incorrect default
    directory

  - CVE-2017-5416: Null dereference crash in HttpChannel

  - CVE-2017-5426: Gecko Media Plugin sandbox is not started
    if seccomp-bpf filter is running

  - CVE-2017-5418: Out of bounds read when parsing HTTP
    digest authorization responses

  - CVE-2017-5419: Repeated authentication prompts lead to
    DOS attack

  - CVE-2017-5405: FTP response codes can cause use of
    uninitialized values for ports

  - CVE-2017-5421: Print preview spoofing

  - CVE-2017-5422: DOS attack by using view-source: protocol
    repeatedly in one hyperlink

  - CVE-2017-5399: Memory safety bugs fixed in Thunderbird
    52

  - CVE-2017-5398: Memory safety bugs fixed in Thunderbird
    52 and Thunderbird 45.8

The following non-security changes are included :

  - Background images not working and other issues related
    to embedded images when composing email have been fixed

  - Google Oauth setup can sometimes not progress to the
    next step

  - Clicking on a link in an email may not open this link in
    the external browser

  - addon blocklist updates

  - enable ALSA for systems without PulseAudio

  - Optionally remove corresponding data files when removing
    an account

  - Possibility to copy message filter

  - Calendar: Event can now be created and edited in a tab

  - Calendar: Processing of received invitation counter
    proposals

  - Chat: Support Twitter Direct Messages

  - Chat: Liking and favoriting in Twitter

  - Chat: Removed Yahoo! Messenger support"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035082"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaThunderbird-52.1.0-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaThunderbird-buildsymbols-52.1.0-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaThunderbird-debuginfo-52.1.0-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaThunderbird-debugsource-52.1.0-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaThunderbird-devel-52.1.0-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaThunderbird-translations-common-52.1.0-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaThunderbird-translations-other-52.1.0-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-52.1.0-41.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-buildsymbols-52.1.0-41.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-debuginfo-52.1.0-41.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-debugsource-52.1.0-41.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-devel-52.1.0-41.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-translations-common-52.1.0-41.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-translations-other-52.1.0-41.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / MozillaThunderbird-buildsymbols / etc");
}

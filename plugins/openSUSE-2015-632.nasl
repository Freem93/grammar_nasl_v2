#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-632.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86282);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/11/08 16:01:24 $");

  script_cve_id("CVE-2015-4500", "CVE-2015-4501", "CVE-2015-4502", "CVE-2015-4503", "CVE-2015-4504", "CVE-2015-4505", "CVE-2015-4506", "CVE-2015-4507", "CVE-2015-4509", "CVE-2015-4510", "CVE-2015-4511", "CVE-2015-4512", "CVE-2015-4516", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7178", "CVE-2015-7179", "CVE-2015-7180");

  script_name(english:"openSUSE Security Update : seamonkey (openSUSE-2015-632)");
  script_summary(english:"Check for the openSUSE-2015-632 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"seamonkey was updated to fix 25 security issues.

These security issues were fixed :

  - CVE-2015-4520: Mozilla Firefox before 41.0 and Firefox
    ESR 38.x before 38.3 allowed remote attackers to bypass
    CORS preflight protection mechanisms by leveraging (1)
    duplicate cache-key generation or (2) retrieval of a
    value from an incorrect HTTP Access-Control-* response
    header (bsc#947003).

  - CVE-2015-4521: The ConvertDialogOptions function in
    Mozilla Firefox before 41.0 and Firefox ESR 38.x before
    38.3 might allowed remote attackers to cause a denial of
    service (memory corruption and application crash) or
    possibly have unspecified other impact via unknown
    vectors (bsc#947003).

  - CVE-2015-4522: The nsUnicodeToUTF8::GetMaxLength
    function in Mozilla Firefox before 41.0 and Firefox ESR
    38.x before 38.3 might allowed remote attackers to cause
    a denial of service (memory corruption and application
    crash) or possibly have unspecified other impact via
    unknown vectors, related to an 'overflow (bsc#947003).

  - CVE-2015-4502: js/src/proxy/Proxy.cpp in Mozilla Firefox
    before 41.0 mishandled certain receiver arguments, which
    allowed remote attackers to bypass intended window
    access restrictions via a crafted website (bsc#947003).

  - CVE-2015-4503: The TCP Socket API implementation in
    Mozilla Firefox before 41.0 mishandled array boundaries
    that were established with a navigator.mozTCPSocket.open
    method call and send method calls, which allowed remote
    TCP servers to obtain sensitive information from process
    memory by reading packet data, as demonstrated by
    availability of this API in a Firefox OS application
    (bsc#947003).

  - CVE-2015-4500: Multiple unspecified vulnerabilities in
    the browser engine in Mozilla Firefox before 41.0 and
    Firefox ESR 38.x before 38.3 allowed remote attackers to
    cause a denial of service (memory corruption and
    application crash) or possibly execute arbitrary code
    via unknown vectors (bsc#947003).

  - CVE-2015-4501: Multiple unspecified vulnerabilities in
    the browser engine in Mozilla Firefox before 41.0
    allowed remote attackers to cause a denial of service
    (memory corruption and application crash) or possibly
    execute arbitrary code via unknown vectors (bsc#947003).

  - CVE-2015-4506: Buffer overflow in the
    vp9_init_context_buffers function in libvpx, as used in
    Mozilla Firefox before 41.0 and Firefox ESR 38.x before
    38.3, allowed remote attackers to execute arbitrary code
    via a crafted VP9 file (bsc#947003).

  - CVE-2015-4507: The SavedStacks class in the JavaScript
    implementation in Mozilla Firefox before 41.0, when the
    Debugger API is enabled, allowed remote attackers to
    cause a denial of service (getSlotRef assertion failure
    and application exit) or possibly execute arbitrary code
    via a crafted website (bsc#947003).

  - CVE-2015-4504: The lut_inverse_interp16 function in the
    QCMS library in Mozilla Firefox before 41.0 allowed
    remote attackers to obtain sensitive information or
    cause a denial of service (buffer over-read and
    application crash) via crafted attributes in the ICC 4
    profile of an image (bsc#947003).

  - CVE-2015-4505: updater.exe in Mozilla Firefox before
    41.0 and Firefox ESR 38.x before 38.3 on Windows allowed
    local users to write to arbitrary files by conducting a
    junction attack and waiting for an update operation by
    the Mozilla Maintenance Service (bsc#947003).

  - CVE-2015-7180: The ReadbackResultWriterD3D11::Run
    function in Mozilla Firefox before 41.0 and Firefox ESR
    38.x before 38.3 misinterprets the return value of a
    function call, which might allowed remote attackers to
    cause a denial of service (memory corruption and
    application crash) or possibly have unspecified other
    impact via unknown vectors (bsc#947003).

  - CVE-2015-4509: Use-after-free vulnerability in the
    HTMLVideoElement interface in Mozilla Firefox before
    41.0 and Firefox ESR 38.x before 38.3 allowed remote
    attackers to execute arbitrary code via crafted
    JavaScript code that modifies the URI table of a media
    element, aka ZDI-CAN-3176 (bsc#947003).

  - CVE-2015-7178: The ProgramBinary::linkAttributes
    function in libGLES in ANGLE, as used in Mozilla Firefox
    before 41.0 and Firefox ESR 38.x before 38.3 on Windows,
    mishandles shader access, which allowed remote attackers
    to execute arbitrary code or cause a denial of service
    (memory corruption and application crash) via crafted
    (1) OpenGL or (2) WebGL content (bsc#947003).

  - CVE-2015-7179: The
    VertexBufferInterface::reserveVertexSpace function in
    libGLES in ANGLE, as used in Mozilla Firefox before 41.0
    and Firefox ESR 38.x before 38.3 on Windows, incorrectly
    allocates memory for shader attribute arrays, which
    allowed remote attackers to execute arbitrary code or
    cause a denial of service (buffer overflow and
    application crash) via crafted (1) OpenGL or (2) WebGL
    content (bsc#947003).

  - CVE-2015-7176: The AnimationThread function in Mozilla
    Firefox before 41.0 and Firefox ESR 38.x before 38.3
    used an incorrect argument to the sscanf function, which
    might allowed remote attackers to cause a denial of
    service (stack-based buffer overflow and application
    crash) or possibly have unspecified other impact via
    unknown vectors (bsc#947003).

  - CVE-2015-7177: The InitTextures function in Mozilla
    Firefox before 41.0 and Firefox ESR 38.x before 38.3
    might allowed remote attackers to cause a denial of
    service (memory corruption and application crash) or
    possibly have unspecified other impact via unknown
    vectors (bsc#947003).

  - CVE-2015-7174: The nsAttrAndChildArray::GrowBy function
    in Mozilla Firefox before 41.0 and Firefox ESR 38.x
    before 38.3 might allowed remote attackers to cause a
    denial of service (memory corruption and application
    crash) or possibly have unspecified other impact via
    unknown vectors, related to an 'overflow (bsc#947003).

  - CVE-2015-7175: The XULContentSinkImpl::AddText function
    in Mozilla Firefox before 41.0 and Firefox ESR 38.x
    before 38.3 might allowed remote attackers to cause a
    denial of service (memory corruption and application
    crash) or possibly have unspecified other impact via
    unknown vectors, related to an 'overflow (bsc#947003).

  - CVE-2015-4511: Heap-based buffer overflow in the
    nestegg_track_codec_data function in Mozilla Firefox
    before 41.0 and Firefox ESR 38.x before 38.3 allowed
    remote attackers to execute arbitrary code via a crafted
    header in a WebM video (bsc#947003).

  - CVE-2015-4510: Race condition in the
    WorkerPrivate::NotifyFeatures function in Mozilla
    Firefox before 41.0 allowed remote attackers to execute
    arbitrary code or cause a denial of service
    (use-after-free and application crash) by leveraging
    improper interaction between shared workers and the
    IndexedDB implementation (bsc#947003).

  - CVE-2015-4512: gfx/2d/DataSurfaceHelpers.cpp in Mozilla
    Firefox before 41.0 on Linux improperly attempts to use
    the Cairo library with 32-bit color-depth surface
    creation followed by 16-bit color-depth surface display,
    which allowed remote attackers to obtain sensitive
    information from process memory or cause a denial of
    service (out-of-bounds read) by using a CANVAS element
    to trigger 2D rendering (bsc#947003).

  - CVE-2015-4517: NetworkUtils.cpp in Mozilla Firefox
    before 41.0 and Firefox ESR 38.x before 38.3 might
    allowed remote attackers to cause a denial of service
    (memory corruption and application crash) or possibly
    have unspecified other impact via unknown vectors
    (bsc#947003).

  - CVE-2015-4516: Mozilla Firefox before 41.0 allowed
    remote attackers to bypass certain ECMAScript 5 (aka
    ES5) API protection mechanisms and modify immutable
    properties, and consequently execute arbitrary
    JavaScript code with chrome privileges, via a crafted
    web page that did not use ES5 APIs (bsc#947003).

  - CVE-2015-4519: Mozilla Firefox before 41.0 and Firefox
    ESR 38.x before 38.3 allowed user-assisted remote
    attackers to bypass intended access restrictions and
    discover a redirect's target URL via crafted JavaScript
    code that executes after a drag-and-drop action of an
    image into a TEXTBOX element (bsc#947003)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=935979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=947003"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-2.38-56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-debuginfo-2.38-56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-debugsource-2.38-56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-dom-inspector-2.38-56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-irc-2.38-56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-translations-common-2.38-56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-translations-other-2.38-56.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-2.38-20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-debuginfo-2.38-20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-debugsource-2.38-20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-dom-inspector-2.38-20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-irc-2.38-20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-translations-common-2.38-20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-translations-other-2.38-20.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey / seamonkey-debuginfo / seamonkey-debugsource / etc");
}

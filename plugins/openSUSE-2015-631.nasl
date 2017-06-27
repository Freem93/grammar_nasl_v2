#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-631.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86281);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/11/08 16:01:24 $");

  script_cve_id("CVE-2015-4500", "CVE-2015-4505", "CVE-2015-4506", "CVE-2015-4509", "CVE-2015-4511", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7178", "CVE-2015-7179", "CVE-2015-7180");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2015-631)");
  script_summary(english:"Check for the openSUSE-2015-631 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaThunderbird was updated to fix 17 security issues.

These security issues were fixed :

  - CVE-2015-4509: Use-after-free vulnerability in the
    HTMLVideoElement interface in Mozilla Firefox before
    41.0 and Firefox ESR 38.x before 38.3 allowed remote
    attackers to execute arbitrary code via crafted
    JavaScript code that modifies the URI table of a media
    element, aka ZDI-CAN-3176 (bsc#947003).

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

  - CVE-2015-4500: Multiple unspecified vulnerabilities in
    the browser engine in Mozilla Firefox before 41.0 and
    Firefox ESR 38.x before 38.3 allowed remote attackers to
    cause a denial of service (memory corruption and
    application crash) or possibly execute arbitrary code
    via unknown vectors (bsc#947003).

  - CVE-2015-4511: Heap-based buffer overflow in the
    nestegg_track_codec_data function in Mozilla Firefox
    before 41.0 and Firefox ESR 38.x before 38.3 allowed
    remote attackers to execute arbitrary code via a crafted
    header in a WebM video (bsc#947003).

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

  - CVE-2015-4506: Buffer overflow in the
    vp9_init_context_buffers function in libvpx, as used in
    Mozilla Firefox before 41.0 and Firefox ESR 38.x before
    38.3, allowed remote attackers to execute arbitrary code
    via a crafted VP9 file (bsc#947003).

  - CVE-2015-4517: NetworkUtils.cpp in Mozilla Firefox
    before 41.0 and Firefox ESR 38.x before 38.3 might
    allowed remote attackers to cause a denial of service
    (memory corruption and application crash) or possibly
    have unspecified other impact via unknown vectors
    (bsc#947003).

  - CVE-2015-4505: updater.exe in Mozilla Firefox before
    41.0 and Firefox ESR 38.x before 38.3 on Windows allowed
    local users to write to arbitrary files by conducting a
    junction attack and waiting for an update operation by
    the Mozilla Maintenance Service (bsc#947003).

  - CVE-2015-4519: Mozilla Firefox before 41.0 and Firefox
    ESR 38.x before 38.3 allowed user-assisted remote
    attackers to bypass intended access restrictions and
    discover a redirect's target URL via crafted JavaScript
    code that executes after a drag-and-drop action of an
    image into a TEXTBOX element (bsc#947003).

  - CVE-2015-7180: The ReadbackResultWriterD3D11::Run
    function in Mozilla Firefox before 41.0 and Firefox ESR
    38.x before 38.3 misinterprets the return value of a
    function call, which might allowed remote attackers to
    cause a denial of service (memory corruption and
    application crash) or possibly have unspecified other
    impact via unknown vectors (bsc#947003).

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
    unknown vectors, related to an 'overflow (bsc#947003)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=947003"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/01");
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

if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-38.3.0-70.65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-buildsymbols-38.3.0-70.65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debuginfo-38.3.0-70.65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debugsource-38.3.0-70.65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-devel-38.3.0-70.65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-common-38.3.0-70.65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-other-38.3.0-70.65.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-38.3.0-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-buildsymbols-38.3.0-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debuginfo-38.3.0-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debugsource-38.3.0-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-devel-38.3.0-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-common-38.3.0-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-other-38.3.0-28.1") ) flag++;

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

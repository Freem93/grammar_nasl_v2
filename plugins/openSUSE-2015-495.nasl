#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-495.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(84864);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2015-0821", "CVE-2015-2721", "CVE-2015-2722", "CVE-2015-2724", "CVE-2015-2725", "CVE-2015-2727", "CVE-2015-2728", "CVE-2015-2729", "CVE-2015-2730", "CVE-2015-2731", "CVE-2015-2733", "CVE-2015-2734", "CVE-2015-2735", "CVE-2015-2736", "CVE-2015-2737", "CVE-2015-2738", "CVE-2015-2739", "CVE-2015-2740", "CVE-2015-2741", "CVE-2015-2743", "CVE-2015-4000");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2015-495) (Logjam)");
  script_summary(english:"Check for the openSUSE-2015-495 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaThunderbird was updated to fix 20 security issues.

These security issues were fixed :

  - CVE-2015-2727: Mozilla Firefox 38.0 and Firefox ESR 38.0
    allowed user-assisted remote attackers to read arbitrary
    files or execute arbitrary JavaScript code with chrome
    privileges via a crafted website that is accessed with
    unspecified mouse and keyboard actions. NOTE: this
    vulnerability exists because of a CVE-2015-0821
    regression (bsc#935979).

  - CVE-2015-2725: Multiple unspecified vulnerabilities in
    the browser engine in Mozilla Firefox before 39.0,
    Firefox ESR 38.x before 38.1, and Thunderbird before
    38.1 allowed remote attackers to cause a denial of
    service (memory corruption and application crash) or
    possibly execute arbitrary code via unknown vectors
    (bsc#935979).

  - CVE-2015-2736: The nsZipArchive::BuildFileList function
    in Mozilla Firefox before 39.0, Firefox ESR 31.x before
    31.8 and 38.x before 38.1, and Thunderbird before 38.1
    accesses unintended memory locations, which allowed
    remote attackers to have an unspecified impact via a
    crafted ZIP archive (bsc#935979).

  - CVE-2015-2724: Multiple unspecified vulnerabilities in
    the browser engine in Mozilla Firefox before 39.0,
    Firefox ESR 31.x before 31.8 and 38.x before 38.1, and
    Thunderbird before 38.1 allowed remote attackers to
    cause a denial of service (memory corruption and
    application crash) or possibly execute arbitrary code
    via unknown vectors (bsc#935979).

  - CVE-2015-2730: Mozilla Network Security Services (NSS)
    before 3.19.1, as used in Mozilla Firefox before 39.0,
    Firefox ESR 31.x before 31.8 and 38.x before 38.1, and
    other products, did not properly perform Elliptical
    Curve Cryptography (ECC) multiplications, which made it
    easier for remote attackers to spoof ECDSA signatures
    via unspecified vectors (bsc#935979).

  - CVE-2015-2743: PDF.js in Mozilla Firefox before 39.0 and
    Firefox ESR 31.x before 31.8 and 38.x before 38.1
    enables excessive privileges for internal Workers, which
    might allowed remote attackers to execute arbitrary code
    by leveraging a Same Origin Policy bypass (bsc#935979).

  - CVE-2015-2740: Buffer overflow in the
    nsXMLHttpRequest::AppendToResponseText function in
    Mozilla Firefox before 39.0, Firefox ESR 31.x before
    31.8 and 38.x before 38.1, and Thunderbird before 38.1
    might allowed remote attackers to cause a denial of
    service or have unspecified other impact via unknown
    vectors (bsc#935979).

  - CVE-2015-2741: Mozilla Firefox before 39.0, Firefox ESR
    38.x before 38.1, and Thunderbird before 38.1 do not
    enforce key pinning upon encountering an X.509
    certificate problem that generates a user dialog, which
    allowed user-assisted man-in-the-middle attackers to
    bypass intended access restrictions by triggering a (1)
    expired certificate or (2) mismatched hostname for a
    domain with pinning enabled (bsc#935979).

  - CVE-2015-2728: The IndexedDatabaseManager class in the
    IndexedDB implementation in Mozilla Firefox before 39.0
    and Firefox ESR 31.x before 31.8 and 38.x before 38.1
    misinterprets an unspecified IDBDatabase field as a
    pointer, which allowed remote attackers to execute
    arbitrary code or cause a denial of service (memory
    corruption and application crash) via unspecified
    vectors, related to a 'type confusion' issue
    (bsc#935979).

  - CVE-2015-2729: The
    AudioParamTimeline::AudioNodeInputValue function in the
    Web Audio implementation in Mozilla Firefox before 39.0
    and Firefox ESR 38.x before 38.1 did not properly
    calculate an oscillator rendering range, which allowed
    remote attackers to obtain sensitive information from
    process memory or cause a denial of service
    (out-of-bounds read) via unspecified vectors
    (bsc#935979).

  - CVE-2015-2739: The ArrayBufferBuilder::append function
    in Mozilla Firefox before 39.0, Firefox ESR 31.x before
    31.8 and 38.x before 38.1, and Thunderbird before 38.1
    accesses unintended memory locations, which has
    unspecified impact and attack vectors (bsc#935979).

  - CVE-2015-2738: The
    YCbCrImageDataDeserializer::ToDataSourceSurface function
    in the YCbCr implementation in Mozilla Firefox before
    39.0, Firefox ESR 31.x before 31.8 and 38.x before 38.1,
    and Thunderbird before 38.1 reads data from
    uninitialized memory locations, which has unspecified
    impact and attack vectors (bsc#935979).

  - CVE-2015-2737: The rx::d3d11::SetBufferData function in
    the Direct3D 11 implementation in Mozilla Firefox before
    39.0, Firefox ESR 31.x before 31.8 and 38.x before 38.1,
    and Thunderbird before 38.1 reads data from
    uninitialized memory locations, which has unspecified
    impact and attack vectors (bsc#935979).

  - CVE-2015-2721: Mozilla Network Security Services (NSS)
    before 3.19, as used in Mozilla Firefox before 39.0,
    Firefox ESR 31.x before 31.8 and 38.x before 38.1,
    Thunderbird before 38.1, and other products, did not
    properly determine state transitions for the TLS state
    machine, which allowed man-in-the-middle attackers to
    defeat cryptographic protection mechanisms by blocking
    messages, as demonstrated by removing a forward-secrecy
    property by blocking a ServerKeyExchange message, aka a
    'SMACK SKIP-TLS' issue (bsc#935979).

  - CVE-2015-2735: nsZipArchive.cpp in Mozilla Firefox
    before 39.0, Firefox ESR 31.x before 31.8 and 38.x
    before 38.1, and Thunderbird before 38.1 accesses
    unintended memory locations, which allowed remote
    attackers to have an unspecified impact via a crafted
    ZIP archive (bsc#935979).

  - CVE-2015-2734: The
    CairoTextureClientD3D9::BorrowDrawTarget function in the
    Direct3D 9 implementation in Mozilla Firefox before
    39.0, Firefox ESR 31.x before 31.8 and 38.x before 38.1,
    and Thunderbird before 38.1 reads data from
    uninitialized memory locations, which has unspecified
    impact and attack vectors (bsc#935979).

  - CVE-2015-2733: Use-after-free vulnerability in the
    CanonicalizeXPCOMParticipant function in Mozilla Firefox
    before 39.0 and Firefox ESR 31.x before 31.8 and 38.x
    before 38.1 allowed remote attackers to execute
    arbitrary code via vectors involving attachment of an
    XMLHttpRequest object to a dedicated worker
    (bsc#935979).

  - CVE-2015-2722: Use-after-free vulnerability in the
    CanonicalizeXPCOMParticipant function in Mozilla Firefox
    before 39.0 and Firefox ESR 31.x before 31.8 and 38.x
    before 38.1 allowed remote attackers to execute
    arbitrary code via vectors involving attachment of an
    XMLHttpRequest object to a shared worker (bsc#935979).

  - CVE-2015-2731: Use-after-free vulnerability in the
    CSPService::ShouldLoad function in the microtask
    implementation in Mozilla Firefox before 39.0, Firefox
    ESR 38.x before 38.1, and Thunderbird before 38.1
    allowed remote attackers to execute arbitrary code by
    leveraging client-side JavaScript that triggers removal
    of a DOM object on the basis of a Content Policy
    (bsc#935979).

  - CVE-2015-4000: The TLS protocol 1.2 and earlier, when a
    DHE_EXPORT ciphersuite is enabled on a server but not on
    a client, did not properly convey a DHE_EXPORT choice,
    which allowed man-in-the-middle attackers to conduct
    cipher-downgrade attacks by rewriting a ClientHello with
    DHE replaced by DHE_EXPORT and then rewriting a
    ServerHello with DHE_EXPORT replaced by DHE, aka the
    'Logjam' issue (bsc#931600)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=935979"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-38.1.0-70.57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-buildsymbols-38.1.0-70.57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debuginfo-38.1.0-70.57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debugsource-38.1.0-70.57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-devel-38.1.0-70.57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-common-38.1.0-70.57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-other-38.1.0-70.57.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-38.1.0-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-buildsymbols-38.1.0-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debuginfo-38.1.0-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debugsource-38.1.0-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-devel-38.1.0-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-common-38.1.0-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-other-38.1.0-22.1") ) flag++;

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

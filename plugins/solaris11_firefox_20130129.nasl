#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80609);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/21 15:53:44 $");

  script_cve_id("CVE-2012-1960", "CVE-2012-1970", "CVE-2012-1971", "CVE-2012-1972", "CVE-2012-1973", "CVE-2012-1974", "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-3956", "CVE-2012-3957", "CVE-2012-3958", "CVE-2012-3959", "CVE-2012-3960", "CVE-2012-3961", "CVE-2012-3962", "CVE-2012-3963", "CVE-2012-3964", "CVE-2012-3966", "CVE-2012-3967", "CVE-2012-3968", "CVE-2012-3969", "CVE-2012-3970", "CVE-2012-3972", "CVE-2012-3974", "CVE-2012-3976", "CVE-2012-3978", "CVE-2012-3980");

  script_name(english:"Oracle Solaris Third-Party Patch Update : firefox (multiple_vulnerabilities_in_firefox)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - The qcms_transform_data_rgb_out_lut_sse2 function in the
    QCMS implementation in Mozilla Firefox 4.x through 13.0,
    Thunderbird 5.0 through 13.0, and SeaMonkey before 2.11
    might allow remote attackers to obtain sensitive
    information from process memory via a crafted color
    profile that triggers an out-of-bounds read operation.
    (CVE-2012-1960)

  - Multiple unspecified vulnerabilities in the browser
    engine in Mozilla Firefox before 15.0, Firefox ESR 10.x
    before 10.0.7, Thunderbird before 15.0, Thunderbird ESR
    10.x before 10.0.7, and SeaMonkey before 2.12 allow
    remote attackers to cause a denial of service (memory
    corruption and application crash) or possibly execute
    arbitrary code via unknown vectors. (CVE-2012-1970)

  - Multiple unspecified vulnerabilities in the browser
    engine in Mozilla Firefox before 15.0, Thunderbird
    before 15.0, and SeaMonkey before 2.12 allow remote
    attackers to cause a denial of service (memory
    corruption and application crash) or possibly execute
    arbitrary code via vectors related to garbage collection
    after certain MethodJIT execution, and unknown other
    vectors. (CVE-2012-1971)

  - Use-after-free vulnerability in the
    nsHTMLEditor::CollapseAdjacentTextNodes function in
    Mozilla Firefox before 15.0, Firefox ESR 10.x before
    10.0.7, Thunderbird before 15.0, Thunderbird ESR 10.x
    before 10.0.7, and SeaMonkey before 2.12 allows remote
    attackers to execute arbitrary code or cause a denial of
    service (heap memory corruption) via unspecified
    vectors. (CVE-2012-1972)

  - Use-after-free vulnerability in the
    nsObjectLoadingContent::LoadObject function in Mozilla
    Firefox before 15.0, Firefox ESR 10.x before 10.0.7,
    Thunderbird before 15.0, Thunderbird ESR 10.x before
    10.0.7, and SeaMonkey before 2.12 allows remote
    attackers to execute arbitrary code or cause a denial of
    service (heap memory corruption) via unspecified
    vectors. (CVE-2012-1973)

  - Use-after-free vulnerability in the
    gfxTextRun::CanBreakLineBefore function in Mozilla
    Firefox before 15.0, Firefox ESR 10.x before 10.0.7,
    Thunderbird before 15.0, Thunderbird ESR 10.x before
    10.0.7, and SeaMonkey before 2.12 allows remote
    attackers to execute arbitrary code or cause a denial of
    service (heap memory corruption) via unspecified
    vectors. (CVE-2012-1974)

  - Use-after-free vulnerability in the
    PresShell::CompleteMove function in Mozilla Firefox
    before 15.0, Firefox ESR 10.x before 10.0.7, Thunderbird
    before 15.0, Thunderbird ESR 10.x before 10.0.7, and
    SeaMonkey before 2.12 allows remote attackers to execute
    arbitrary code or cause a denial of service (heap memory
    corruption) via unspecified vectors. (CVE-2012-1975)

  - Use-after-free vulnerability in the
    nsHTMLSelectElement::SubmitNamesValues function in
    Mozilla Firefox before 15.0, Firefox ESR 10.x before
    10.0.7, Thunderbird before 15.0, Thunderbird ESR 10.x
    before 10.0.7, and SeaMonkey before 2.12 allows remote
    attackers to execute arbitrary code or cause a denial of
    service (heap memory corruption) via unspecified
    vectors. (CVE-2012-1976)

  - Use-after-free vulnerability in the
    MediaStreamGraphThreadRunnable::Run function in Mozilla
    Firefox before 15.0, Firefox ESR 10.x before 10.0.7,
    Thunderbird before 15.0, Thunderbird ESR 10.x before
    10.0.7, and SeaMonkey before 2.12 allows remote
    attackers to execute arbitrary code or cause a denial of
    service (heap memory corruption) via unspecified
    vectors. (CVE-2012-3956)

  - Heap-based buffer overflow in the
    nsBlockFrame::MarkLineDirty function in Mozilla Firefox
    before 15.0, Firefox ESR 10.x before 10.0.7, Thunderbird
    before 15.0, Thunderbird ESR 10.x before 10.0.7, and
    SeaMonkey before 2.12 allows remote attackers to execute
    arbitrary code via unspecified vectors. (CVE-2012-3957)

  - Use-after-free vulnerability in the
    nsHTMLEditRules::DeleteNonTableElements function in
    Mozilla Firefox before 15.0, Firefox ESR 10.x before
    10.0.7, Thunderbird before 15.0, Thunderbird ESR 10.x
    before 10.0.7, and SeaMonkey before 2.12 allows remote
    attackers to execute arbitrary code or cause a denial of
    service (heap memory corruption) via unspecified
    vectors. (CVE-2012-3958)

  - Use-after-free vulnerability in the
    nsRangeUpdater::SelAdjDeleteNode function in Mozilla
    Firefox before 15.0, Firefox ESR 10.x before 10.0.7,
    Thunderbird before 15.0, Thunderbird ESR 10.x before
    10.0.7, and SeaMonkey before 2.12 allows remote
    attackers to execute arbitrary code or cause a denial of
    service (heap memory corruption) via unspecified
    vectors. (CVE-2012-3959)

  - Use-after-free vulnerability in the
    mozSpellChecker::SetCurrentDictionary function in
    Mozilla Firefox before 15.0, Firefox ESR 10.x before
    10.0.7, Thunderbird before 15.0, Thunderbird ESR 10.x
    before 10.0.7, and SeaMonkey before 2.12 allows remote
    attackers to execute arbitrary code or cause a denial of
    service (heap memory corruption) via unspecified
    vectors. (CVE-2012-3960)

  - Use-after-free vulnerability in the RangeData
    implementation in Mozilla Firefox before 15.0, Firefox
    ESR 10.x before 10.0.7, Thunderbird before 15.0,
    Thunderbird ESR 10.x before 10.0.7, and SeaMonkey before
    2.12 allows remote attackers to execute arbitrary code
    or cause a denial of service (heap memory corruption)
    via unspecified vectors. (CVE-2012-3961)

  - Mozilla Firefox before 15.0, Firefox ESR 10.x before
    10.0.7, Thunderbird before 15.0, Thunderbird ESR 10.x
    before 10.0.7, and SeaMonkey before 2.12 do not properly
    iterate through the characters in a text run, which
    allows remote attackers to execute arbitrary code via a
    crafted document. (CVE-2012-3962)

  - Use-after-free vulnerability in the
    js::gc::MapAllocToTraceKind function in Mozilla Firefox
    before 15.0, Firefox ESR 10.x before 10.0.7, Thunderbird
    before 15.0, Thunderbird ESR 10.x before 10.0.7, and
    SeaMonkey before 2.12 allows remote attackers to execute
    arbitrary code via unspecified vectors. (CVE-2012-3963)

  - Use-after-free vulnerability in the
    gfxTextRun::GetUserData function in Mozilla Firefox
    before 15.0, Firefox ESR 10.x before 10.0.7, Thunderbird
    before 15.0, Thunderbird ESR 10.x before 10.0.7, and
    SeaMonkey before 2.12 allows remote attackers to execute
    arbitrary code or cause a denial of service (heap memory
    corruption) via unspecified vectors. (CVE-2012-3964)

  - Mozilla Firefox before 15.0, Firefox ESR 10.x before
    10.0.7, Thunderbird before 15.0, Thunderbird ESR 10.x
    before 10.0.7, and SeaMonkey before 2.12 allow remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption) via a negative height value
    in a BMP image within a .ICO file, related to (1)
    improper handling of the transparency bitmask by the
    nsICODecoder component and (2) improper processing of
    the alpha channel by the nsBMPDecoder component.
    (CVE-2012-3966)

  - The WebGL implementation in Mozilla Firefox before 15.0,
    Firefox ESR 10.x before 10.0.7, Thunderbird before 15.0,
    Thunderbird ESR 10.x before 10.0.7, and SeaMonkey before
    2.12 on Linux, when a large number of sampler uniforms
    are used, does not properly interact with Mesa drivers,
    which allows remote attackers to execute arbitrary code
    or cause a denial of service (stack memory corruption)
    via a crafted web site. (CVE-2012-3967)

  - Use-after-free vulnerability in the WebGL implementation
    in Mozilla Firefox before 15.0, Firefox ESR 10.x before
    10.0.7, Thunderbird before 15.0, Thunderbird ESR 10.x
    before 10.0.7, and SeaMonkey before 2.12 allows remote
    attackers to execute arbitrary code via vectors related
    to deletion of a fragment shader by its accessor.
    (CVE-2012-3968)

  - Integer overflow in the nsSVGFEMorphologyElement::Filter
    function in Mozilla Firefox before 15.0, Firefox ESR
    10.x before 10.0.7, Thunderbird before 15.0, Thunderbird
    ESR 10.x before 10.0.7, and SeaMonkey before 2.12 allows
    remote attackers to execute arbitrary code via a crafted
    SVG filter that triggers an incorrect sum calculation,
    leading to a heap-based buffer overflow. (CVE-2012-3969)

  - Use-after-free vulnerability in the
    nsTArray_base::Length function in Mozilla Firefox before
    15.0, Firefox ESR 10.x before 10.0.7, Thunderbird before
    15.0, Thunderbird ESR 10.x before 10.0.7, and SeaMonkey
    before 2.12 allows remote attackers to execute arbitrary
    code or cause a denial of service (heap memory
    corruption) via vectors involving movement of a
    requiredFeatures attribute from one SVG document to
    another. (CVE-2012-3970)

  - The format-number functionality in the XSLT
    implementation in Mozilla Firefox before 15.0, Firefox
    ESR 10.x before 10.0.7, Thunderbird before 15.0,
    Thunderbird ESR 10.x before 10.0.7, and SeaMonkey before
    2.12 allows remote attackers to obtain sensitive
    information via unspecified vectors that trigger a
    heap-based buffer over-read. (CVE-2012-3972)

  - Untrusted search path vulnerability in the installer in
    Mozilla Firefox before 15.0, Firefox ESR 10.x before
    10.0.7, Thunderbird before 15.0, and Thunderbird ESR
    10.x before 10.0.7 on Windows allows local users to gain
    privileges via a Trojan horse executable file in a root
    directory. (CVE-2012-3974)

  - Mozilla Firefox before 15.0, Firefox ESR 10.x before
    10.0.7, and SeaMonkey before 2.12 do not properly handle
    onLocationChange events during navigation between
    different https sites, which allows remote attackers to
    spoof the X.509 certificate information in the address
    bar via a crafted web page. (CVE-2012-3976)

  - The nsLocation::CheckURL function in Mozilla Firefox
    before 15.0, Firefox ESR 10.x before 10.0.7, Thunderbird
    before 15.0, Thunderbird ESR 10.x before 10.0.7, and
    SeaMonkey before 2.12 does not properly follow the
    security model of the location object, which allows
    remote attackers to bypass intended content-loading
    restrictions or possibly have unspecified other impact
    via vectors involving chrome code. (CVE-2012-3978)

  - The web console in Mozilla Firefox before 15.0, Firefox
    ESR 10.x before 10.0.7, Thunderbird before 15.0, and
    Thunderbird ESR 10.x before 10.0.7 allows user-assisted
    remote attackers to execute arbitrary JavaScript code
    with chrome privileges via a crafted web site that
    injects this code and triggers an eval operation.
    (CVE-2012-3980)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_firefox
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09b23ad2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.2.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:firefox");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^firefox$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.2.0.5.0", sru:"SRU 2.5") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : firefox\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "firefox");

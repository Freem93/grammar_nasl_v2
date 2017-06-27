#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97724);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/07 15:11:00 $");

  script_cve_id(
    "CVE-2017-5029",
    "CVE-2017-5030",
    "CVE-2017-5031",
    "CVE-2017-5032",
    "CVE-2017-5033",
    "CVE-2017-5034",
    "CVE-2017-5035",
    "CVE-2017-5036",
    "CVE-2017-5037",
    "CVE-2017-5038",
    "CVE-2017-5039",
    "CVE-2017-5040",
    "CVE-2017-5041",
    "CVE-2017-5042",
    "CVE-2017-5043",
    "CVE-2017-5044",
    "CVE-2017-5045",
    "CVE-2017-5046"
  );
  script_bugtraq_id(96767);
  script_osvdb_id(
    149635,
    151459,
    152428,
    153215,
    153329,
    153330,
    153331,
    153332,
    153333,
    153334,
    153335,
    153336,
    153337,
    153338,
    153339,
    153340,
    153341,
    153342,
    153343,
    153344,
    153345,
    153346,
    153347,
    153348,
    153349,
    153350,
    153353,
    153354,
    153355,
    153359,
    153372,
    153373,
    153374,
    153375,
    153386,
    153394
  );

  script_name(english:"Google Chrome < 57.0.2987.98 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 57.0.2987.98. It is, therefore, affected by the following
vulnerabilities :

  - An integer overflow condition condition exists in
    libxslt in the xsltAddTextString() function in
    transform.c due to improper validation of user-supplied
    input. An unauthenticated, remote attacker can exploit
    this to cause an out-of-bounds write error, resulting in
    the execution of arbitrary code. (CVE-2017-5029)

  - A flaw exists in Google V8 in the ArrayConcatVisitor
    class in builtins-array.cc due to improper handling of
    JSProxy species. An unauthenticated, remote attacker can
    exploit this to corrupt memory, resulting in a denial of
    service condition or the execution of arbitrary code.
    (CVE-2017-5030)

  - A use-after-free error exists in the ANGLE component due
    to improper handling of buffer storage operations. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2017-5031)

  - An overflow condition exists in Google PDFium in the
    GetTextRunInfo() function in pdfium_page.cc that is
    triggered when processing text runs. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted PDF file, to execute arbitrary code.
    (CVE-2017-5032)

  - A security bypass vulnerability exists in the
    initContentSecurityPolicy() function in Document.cpp due
    to local schemes not inheriting the content security
    policy. An unauthenticated, remote attacker can exploit
    this to bypass the content security policy.
    (CVE-2017-5033)

  - A flaw exists in the OpenJPEG component in the
    m_mct_records() function in j2k.c due to improper
    handling of specially crafted JPEG2000 files. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2017-5034)

  - An unspecified flaw exists in the
    RendererDidNavigateToExistingPage() function in
    navigation_controller_impl.cc that occurs when handling
    data from the renderer process. An unauthenticated,
    remote attacker can exploit this to have an unspecified
    impact on the security UI. (CVE-2017-5035)

  - A use-after-free error exists in Google PDFium in the
    Document class in Document.h due to improper handling of
    'm_Icons' properties. An unauthenticated, remote
    attacker can exploit this to dereference already freed
    memory, resulting in the execution of arbitrary code.
    (CVE-2017-5036)

  - Multiple integer overflow conditions exists in the
    TrackFragmentRun::Parse() function in box_definitions.cc
    due to improper parsing of track fragments in MP4
    content. An unauthenticated, remote attacker can exploit
    this to execute arbitrary code. (CVE-2017-5037)

  - An unspecified use-after-free error occurs when
    GuestView objects inherit the prototypes from the global
    JS object. An unauthenticated, remote attacker can
    exploit this to execute arbitrary code. (CVE-2017-5038)

  - A use-after-free error exists in Google PDFium in the
    GlobalTimer() function in app.cpp due to improper
    handling of timers. An unauthenticated, remote attacker
    can exploit this to execute arbitrary code.
    (CVE-2017-5039)

  - An unspecified flaw exists in Google V8 that allows an
    unauthenticated, remote attacker to disclose sensitive
    information. (CVE-2017-5040)

  - A flaw exists in the Omnibox address bar that allows an
    unauthenticated, remote attacker to spoof an address.
    (CVE-2017-5041)

  - An unspecified flaw exists in the Cast feature that is
    triggered when handling cookies. An unauthenticated,
    remote attacker can exploit this to have an unspecified
    impact. (CVE-2017-5042)

  - A use-after-free error exists in
    guest_view_internal_custom_bindings.cc due to improper
    handling of the GuestViewContainer pointer during a
    GuestView attach operation. An unauthenticated, remote
    attacker can exploit this to execute arbitrary code.
    (CVE-2017-5043)

  - A heap-based overflow condition exists in Google Skia
    that occurs when deserializing SkRegion objects. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2017-5044)

  - An unspecified flaw exists in the XSS auditor that
    allows an unauthenticated, remote attacker to disclose
    sensitive information. (CVE-2017-5045)

  - An unspecified flaw exists in interface_base.cpp.tmpl
    that occurs when handling author scripts interacting
    with Symbol.toPrimitive properties of Location objects.
    An unauthenticated, remote attacker can exploit this to
    disclose sensitive information. (CVE-2017-5046)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2017/03/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?0d061769");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 57.0.2987.98 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:R");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'57.0.2987.98', severity:SECURITY_HOLE);

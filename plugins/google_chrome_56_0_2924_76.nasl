#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96828);

  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/03/20 15:44:32 $");

  script_cve_id(
    "CVE-2017-5006",
    "CVE-2017-5007",
    "CVE-2017-5008",
    "CVE-2017-5009",
    "CVE-2017-5010",
    "CVE-2017-5011",
    "CVE-2017-5012",
    "CVE-2017-5013",
    "CVE-2017-5014",
    "CVE-2017-5015",
    "CVE-2017-5016",
    "CVE-2017-5017",
    "CVE-2017-5018",
    "CVE-2017-5019",
    "CVE-2017-5020",
    "CVE-2017-5021",
    "CVE-2017-5022",
    "CVE-2017-5023",
    "CVE-2017-5024",
    "CVE-2017-5025",
    "CVE-2017-5026",
    "CVE-2017-5027"
  );
  script_bugtraq_id(95792);
  script_osvdb_id(
    150936,
    150937,
    150938,
    150939,
    150940,
    150941,
    150942,
    150943,
    150944,
    150945,
    150946,
    150947,
    150948,
    150949,
    150950,
    150951,
    150952,
    150953,
    150954,
    150966,
    150967,
    150977,
    150978,
    150979,
    150980,
    150981,
    150982,
    150983,
    150984,
    150985,
    150986,
    150987,
    150988,
    150989,
    150990,
    150991,
    150993,
    150994,
    150995,
    150996,
    150997,
    150998,
    152248
  );

  script_name(english:"Google Chrome < 56.0.2924.76 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 56.0.2924.76. It is, therefore, affected by the following
vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists in the
    Document::shutdown() function in dom/Document.cpp due to
    a failure to clear the owner's widget for a frame. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2017-5006)

  - A cross-site scripting (XSS) vulnerability exists in the
    Document::shutdown() function in dom/Document.cpp due to
    a failure to properly suspend pages that are closing,
    but not yet fully closed. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2017-5007)

  - A cross-site scripting (XSS) vulnerability exists in the
    compileAndRunPrivateScript() function in
    PrivateScriptRunner.cpp due to a failure to properly
    protect private scripts. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2017-5008)

  - An out-of-bounds read error exists in the
    UsingFlexibleMode() function in decoding_state.cc due to
    improper handling of frames marked as using flexible
    mode. An unauthenticated, remote attacker can exploit
    this to execute arbitrary code. (CVE-2017-5009)

  - A cross-site scripting (XSS) vulnerability exists in
    css/FontFace.cpp due to improper handling of FontFace
    objects. An unauthenticated, remote attacker can exploit
    this, via a specially crafted request, to execute
    arbitrary script code in a user's browser session.
    (CVE-2017-5010)

  - An information disclosure vulnerability exists in the
    Devtools component due to improper front-end URL
    handling. An unauthenticated, remote attacker can
    exploit this to disclose arbitrary files.
    (CVE-2017-5011)

  - A heap buffer overflow condition exists in Google V8 in
    the SetupAllocatingData() function in objects.h that
    occurs when failing to allocate array buffer contents.
    An unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2017-5012)

  - A flaw exists in the ShouldFocusLocationBarByDefault()
    function in ui/browser.cc that is triggered when
    handling NTP navigations in non-selected tabs. An
    unauthenticated, remote attacker can exploit this to
    spoof the address. (CVE-2017-5013)

  - A heap buffer overflow condition exists in Google Skia
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2017-5014)

  - An unspecified flaw exists in Omnibox that allows an
    unauthenticated, remote attacker to spoof the address.
    (CVE-2017-5015)

  - A flaw exists in the updateVisibleValidationMessage()
    function in html/HTMLFormControlElement.cpp related to
    the form validation bubble being displayed for invisible
    pages. An unauthenticated, remote attacker can exploit
    this to spoof the UI. (CVE-2017-5016)

  - An uninitialized memory access flaw exists in the webm
    video processing implementation that allows an
    unauthenticated, remote attacker to have an unspecified
    impact. (CVE-2017-5017)

  - A cross-site scripting (XSS) vulnerability exists in the
    App Launcher component due to a failure to properly
    validate parameters. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (CVE-2017-5018)

  - A use-after-free error exists in the OnBeforeUnload()
    function in render_frame_impl.cc. An unauthenticated,
    remote attacker can exploit this to execute arbitrary
    code. (CVE-2017-5019)

  - A cross-site scripting (XSS) vulnerability exists in
    Blink due to a failure to properly validate input
    related to chrome://downloads. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (CVE-2017-5020)

  - A use-after-free error exists in the Extensions
    component. An unauthenticated, remote attacker can
    exploit this to execute arbitrary code. (CVE-2017-5021)

  - A security bypass vulnerability exists in
    frame/csp/ContentSecurityPolicy.cpp that allows an
    unauthenticated, remote attacker to bypass the content
    security policy (CSP). (CVE-2017-5022)

  - A type confusion flaw exists in the histogram collector
    feature that is triggered when handling serialized
    histograms. An unauthenticated remote attacker can
    exploit this to crash the browser, resulting in a denial
    of service condition. (CVE-2017-5023)

  - A heap buffer overflow condition exists in FFmpeg in the
    mov_read_uuid() function in libavformat/mov.c due to
    improper handling of overly long UUIDs. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-5024)

  - A heap buffer overflow condition exists in FFmpeg in the
    mov_read_hdlr() function in libavformat/mov.c due to
    improper validation of user-supplied input when handling
    titles. An unauthenticated, remote attacker can exploit
    this to execute arbitrary code. (CVE-2017-5025)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to spoof the UI.
    (CVE-2017-5026)

  - An unspecified flaw exists in Blink that allows an
    unauthenticated, remote attacker to bypass the content
    security policy. (CVE-2017-5027)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2017/01/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?fcdefa5b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 56.0.2924.76 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/27");

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

google_chrome_check_version(installs:installs, fix:'56.0.2924.76', severity:SECURITY_HOLE, xss:TRUE);

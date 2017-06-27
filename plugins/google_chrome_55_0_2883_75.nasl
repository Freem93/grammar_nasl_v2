#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95480);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/06 16:27:35 $");

  script_cve_id(
    "CVE-2016-5203",
    "CVE-2016-5204",
    "CVE-2016-5205",
    "CVE-2016-5206",
    "CVE-2016-5207",
    "CVE-2016-5208",
    "CVE-2016-5209",
    "CVE-2016-5210",
    "CVE-2016-5211",
    "CVE-2016-5212",
    "CVE-2016-5213",
    "CVE-2016-5214",
    "CVE-2016-5215",
    "CVE-2016-5216",
    "CVE-2016-5217",
    "CVE-2016-5218",
    "CVE-2016-5219",
    "CVE-2016-5220",
    "CVE-2016-5221",
    "CVE-2016-5222",
    "CVE-2016-5223",
    "CVE-2016-5224",
    "CVE-2016-5225",
    "CVE-2016-5226",
    "CVE-2016-9650",
    "CVE-2016-9651",
    "CVE-2016-9652"
  );
  script_bugtraq_id(94633);
  script_osvdb_id(
    148065,
    148066,
    148067,
    148068,
    148069,
    148070,
    148071,
    148072,
    148073,
    148074,
    148075,
    148076,
    148077,
    148078,
    148079,
    148080,
    148081,
    148082,
    148083,
    148084,
    148086,
    148087,
    148088,
    148104,
    148105,
    148106,
    148133,
    148134,
    148135
  );

  script_name(english:"Google Chrome < 55.0.2883.75 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 55.0.2883.75. It is, therefore, affected by the following
vulnerabilities :

  - A use-after-free error exists in PDFium in the
    Document::removeField() function within file
    fpdfsdk/javascript/Document.cpp when removing fields
    within a document. An unauthenticated, remote attacker
    can exploit this to dereference already freed memory,
    resulting in the execution of arbitrary code.
    (CVE-2016-5203)

  - A universal cross-site scripting (XSS) vulnerability
    exists in Blink due to improper handling of the 'use'
    SVG element when calling event listeners on a cloned
    node. An unauthenticated, remote attacker can exploit
    this to execute arbitrary script code in a user's
    browser session. (CVE-2016-5204)

  - A universal cross-site scripting (XSS) vulnerability
    exists in Blink due to permitting frame swaps during
    frame detach. An unauthenticated, remote attacker can
    exploit this to execute arbitrary script code in a
    user's browser session. (CVE-2016-5205)

  - A security bypass vulnerability exists in PDFium due to
    a flaw in the DocumentLoader::GetRequest() function
    within file pdf/document_loader.cc when handling
    redirects in the plugin. An unauthenticated, remote
    attacker can exploit this to bypass the same-origin
    policy. (CVE-2016-5206)

  - A universal cross-site scripting (XSS) vulnerability
    exists in Blink, specifically in the
    V8EventListener::getListenerFunction() function within
    file bindings/core/v8/V8EventListener.cpp, due to
    allowing the 'handleEvent' getter to run on forbidden
    scripts. An unauthenticated, remote attacker can exploit
    this to execute arbitrary script code in a user's
    browser session. (CVE-2016-5207)

  - A universal cross-site scripting (XSS) vulnerability
    exists in Blink due to improper handling of triggered
    events (e.g., closing a color chooser for an input
    element). An unauthenticated, remote attacker can
    exploit this to execute arbitrary script code in a
    user's browser session. (CVE-2016-5208)

  - An out-of-bounds write error exists in Blink due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-5209)

  - An out-of-bounds write error exists in PDFium in the
    CWeightTable::GetPixelWeightSize() function within file
    core/fxge/dib/fx_dib_engine.cpp. An unauthenticated,
    remote attacker can exploit this to corrupt memory,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2016-5210)

  - An unspecified use-after-free error exists in PDFium due
    to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    corrupt memory, resulting in a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-5211)

  - A unspecified flaw exists in the DevTools component due
    to improper validation of certain URLs that allows an
    unauthenticated, remote attacker to disclose the content
    of arbitrary files. (CVE-2016-5212)

  - Multiple use-after-free errors exist in the inspector
    component in V8 that allow an unauthenticated, remote
    attacker to execute arbitrary code. (CVE-2016-5213,
    CVE-2016-5219)

  - A file download protection bypass vulnerability exists
    when downloading files that involve 'data:' URIs,
    unknown URI schemes, or overly long URLs. An
    unauthenticated, remote attacker can exploit this to
    cause a file to be downloaded without applying the
    mark-of-the-web. (CVE-2016-5214)

  - A use-after-free error exists in WebAudio within file
    content/renderer/media/renderer_webaudiodevice_impl.cc
    due to improper handling of web audio. An
    unauthenticated, remote attacker can exploit this to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2016-5215)

  - A use-after-free error exists in PDFium, specifically
    within file pdf/pdfium/pdfium_engine.cc, due to improper
    handling of non-visible page unloading. An
    unauthenticated, remote attacker can exploit this to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2016-5216)

  - A flaw exists in PDFium due to the use of unvalidated
    data by the PDF helper extension. An authenticated,
    remote attacker can exploit this to have an unspecified
    impact. No other details are available. (CVE-2016-5217)

  - A flaw exists when handling chrome.tabs API navigations
    and displaying the pending URL. An unauthenticated,
    remote attacker can exploit this to spoof the Omnibox
    address. (CVE-2016-5218)

  - An information disclosure vulnerability exists in
    PDFium, due to improper handling of 'file: navigation',
    that allows an unauthenticated, remote attacker to
    disclose local files. (CVE-2016-5220)

  - An integer overflow condition exists in ANGLE due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    have an unspecified impact. (CVE-2016-5221)

  - A flaw exists in the NavigatorImpl::NavigateToEntry()
    function within file frame_host/navigator_impl.cc due to
    improper handling of invalid URLs. An unauthenticated,
    remote attacker can exploit this to spoof the Omnibox
    address. (CVE-2016-5222)

  - An integer overflow condition exists in PDFium within
    file core/fpdfapi/page/cpdf_page.cpp that allows an
    authenticated, remote attacker to have an unspecified
    impact. No other details are available. (CVE-2016-5223)

  - A security bypass vulnerability exists in the SVG
    component due to denorm handling not being disabled
    before calling Skia filter code. An unauthenticated,
    remote attacker can exploit this to bypass the
    same-origin policy. (CVE-2016-5224)

  - A flaw exists in Blink, specifically in the
    HTMLFormElement::scheduleFormSubmission() function
    within file html/HTMLFormElement.cpp, due to improper
    enforcement of the form-action CSP (Content Security
    Policy). An unauthenticated, remote attacker can exploit
    this to bypass intended access restrictions.
    (CVE-2016-5225)

  - A cross-site scripting (XSS) vulnerability exists in
    Blink within file ui/views/tabs/tab_strip.cc due to
    improper validation of input when dropping JavaScript
    URLs on a tab. An unauthenticated, remote attacker can
    exploit this to execute arbitrary script code in a
    user's browser session. (CVE-2016-5226)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to disclose Content
    Security Policy (CSP) referrers. (CVE-2016-9650)

  - An unspecified flaw exists in V8 within lookup.cc that
    allows unauthorized private property access. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-9651)

  - Multiple other vulnerabilities exist, the most serious
    of which can be exploited by an authenticated, remote
    attacker to execute arbitrary code. (CVE-2016-9652)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://googlechromereleases.blogspot.com/2016/12/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?bfe6e9a5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 55.0.2883.75 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/02");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'55.0.2883.75', severity:SECURITY_HOLE, xss:TRUE);

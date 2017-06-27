#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87206);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:42:40 $");

  script_cve_id(
    "CVE-2015-6764",
    "CVE-2015-6765",
    "CVE-2015-6766",
    "CVE-2015-6767",
    "CVE-2015-6768",
    "CVE-2015-6769",
    "CVE-2015-6770",
    "CVE-2015-6771",
    "CVE-2015-6772",
    "CVE-2015-6773",
    "CVE-2015-6774",
    "CVE-2015-6775",
    "CVE-2015-6776",
    "CVE-2015-6777",
    "CVE-2015-6778",
    "CVE-2015-6779",
    "CVE-2015-6780",
    "CVE-2015-6781",
    "CVE-2015-6782",
    "CVE-2015-6783",
    "CVE-2015-6784",
    "CVE-2015-6785",
    "CVE-2015-6786",
    "CVE-2015-6787"
  );
  script_osvdb_id(
    130971,
    130972,
    130973,
    130974,
    130975,
    130976,
    130977,
    130978,
    130979,
    130980,
    130981,
    130982,
    130983,
    130984,
    130985,
    130986,
    130987,
    130988,
    130989,
    130990,
    130991,
    130992,
    131009,
    131010,
    131011,
    131012,
    131013,
    131014,
    131029,
    131030,
    131031
  );

  script_name(english:"Google Chrome < 47.0.2526.73 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 47.0.2526.73. It is, therefore, affected by multiple
vulnerabilities :

  - An out-of-bounds access error exists in Google V8 that
    is triggered when loading array elements. An attacker
    can exploit this to have an unspecified impact.
    (CVE-2015-6764)

  - A use-after-free error exists that is triggered when
    handling updates. An unauthenticated, remote attacker
    can exploit this to dereference already freed memory,
    resulting in the execution of arbitrary code.
    (CVE-2015-6765)

  - A use-after-free error exists in AppCache that is
    triggered when handling updates. An unauthenticated,
    remote attacker can exploit this to dereference already
    freed memory, resulting in the execution of arbitrary
    code. (CVE-2015-6766)

  - A use-after-free error exists in the
    OnChannelConnected() function. An unauthenticated,
    remote attacker can exploit this to dereference already
    freed memory, resulting in the execution of arbitrary
    code. (CVE-2015-6767)

  - A same-origin bypass vulnerability exists due to a flaw
    that is triggered when handling 'javascript:' URI
    document navigations during page dismissal events. An
    attacker can exploit this to bypass the same-origin
    policy. (CVE-2015-6768)

  - A same-origin bypass vulnerability exists due to a flaw
    that is triggered when committing a provisional load and
    handling the window proxy. An attacker can exploit this
    to bypass the same-origin policy. (CVE-2015-6769)

  - A same-origin bypass vulnerability exists due to a flaw
    in DOM. An attacker can exploit this to bypass the
    same-origin policy. (CVE-2015-6770)

  - An out-of-bounds access error exists in Google V8
    related Map and Filter array construction. An attacker
    can exploit this to have an unspecified impact.
    (CVE-2015-6771)

  - A same-origin bypass vulnerability exists due to a flaw
    that is triggered when navigating to a 'javascript:' URI
    and detaching the document. An attacker can exploit this
    to bypass the same-origin policy. (CVE-2015-6772)

  - An out-of-bounds access error exists in Google Skia
    related to the handling of rows. An attacker can exploit
    this to have an unspecified impact. (CVE-2015-6773)

  - A use-after-free error exists in the GetLoadTimes()
    function. An unauthenticated, remote attacker can
    exploit this to dereference already freed memory,
    resulting in the execution of arbitrary code.
    (CVE-2015-6774)

  - A type confusion error exists in Google PDFium. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2015-6775)

  - An heap-based overflow condition exists in OpenJPEG in
    the opj_dwt_decode() function due to improper validation
    of user-supplied input. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2015-6776)

  - A use-after-free error exists in the
    notifyNodeInsertedInternal() function. An
    unauthenticated, remote attacker can exploit this to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2015-6777)

  - An out-of-bounds access error exists in Google PDFium.
    An attacker can exploit this to have an unspecified
    impact. (CVE-2015-6778)

  - A security bypass vulnerability exists in Google PDFium
    due to improper restriction of certain URLs (e.g.,
    working links to 'chrome://' are allowed). An attacker
    can exploit this to bypass intended access restrictions.
    (CVE-2015-6779)

  - A use-after-free error exists that is triggered when
    handling the origin info bubble. An unauthenticated,
    remote attacker can exploit this to dereference already
    freed memory, resulting in the execution of arbitrary
    code. (CVE-2015-6780)

  - An integer overflow condition exists in Google sfntly
    due to improper validation of user-supplied input. An
    attacker can exploit this to have an unspecified impact.
    (CVE-2015-6781)

  - A content spoofing vulnerability exists due to a flaw in
    the Document::open() function that is triggered when
    handling page dismissal events. An attacker can exploit
    this to spoof omnibox content. (CVE-2015-6782)

  - A security bypass vulnerability exists in Google Android
    Crazy Linker that is triggered when searching for the
    zip EOCD record signature. An attacker can exploit this
    to bypass signature validation. (CVE-2015-6783)

  - A flaw exists that is triggered as '--' in the page URL
    is not escaped by the page serializer when saving pages.
    An attacker can exploit this to inject text that is
    treated as HTML content. (CVE-2015-6784)

  - A security bypass vulnerability exists that is triggered
    when matching Content Security Policy (CSP) source lists
    containing wildcards. An attacker can exploit this to
    bypass CSP restrictions. (CVE-2015-6785)

  - A security bypass vulnerability exists due to a flaw
    that is triggered when matching 'data:', 'blob:', and
    'filesystem:' URIs against wildcards. An attacker can
    exploit this to bypass CSP restrictions. (CVE-2015-6786)

  - Multiple unspecified flaws exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2015-6787)");
  # http://googlechromereleases.blogspot.in/2015/12/stable-channel-update.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?77759993");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 47.0.2526.73 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/04");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'47.0.2526.73', severity:SECURITY_HOLE);

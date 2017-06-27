#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82826);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id(
    "CVE-2015-1235",
    "CVE-2015-1236",
    "CVE-2015-1237",
    "CVE-2015-1238",
    "CVE-2015-1240",
    "CVE-2015-1241",
    "CVE-2015-1242",
    "CVE-2015-1244",
    "CVE-2015-1245",
    "CVE-2015-1246",
    "CVE-2015-1247",
    "CVE-2015-1248",
    "CVE-2015-1249",
    "CVE-2015-3333",
    "CVE-2015-3334",
    "CVE-2015-3335"
  );
  script_bugtraq_id(
    72715,
    74165,
    74167,
    74221,
    74225
  );
  script_osvdb_id(
    120749,
    120750,
    120751,
    120752,
    120753,
    120754,
    120755,
    120756,
    120757,
    120758,
    120759,
    120760,
    120805,
    120806,
    120827,
    120828,
    120829,
    120830,
    120831,
    120832,
    120852,
    120853,
    120854,
    120864,
    120866,
    120867,
    120868,
    120869,
    120882,
    120883,
    120884,
    120909,
    120910,
    120911,
    120912,
    120913,
    120914,
    120915,
    120916,
    120917,
    120918
  );

  script_name(english:"Google Chrome < 42.0.2311.90 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 42.0.2311.90. It is, therefore, affected by multiple
vulnerabilities :

  - A cross-origin bypass vulnerability exists due to an
    unspecified flaw in the HTML parser. (CVE-2015-1235)

  - A cross-origin bypass vulnerability exists due to a flaw
    in MediaElementAudioSourceNode.cpp when handling audio
    content. (CVE-2015-1236)

  - A use-after-free error exists in render_frame_impl.cc
    due to improper handling of a frame when it receives
    messages while detaching. An attacker can exploit this
    flaw to dereference already freed memory and execute
    arbitrary code. (CVE-2015-1237)

  - An unspecified out-of-bounds write flaw exists in the
    Skia filters. (CVE-2015-1238)

  - An out-of-bounds read flaw exists in WebGL due to
    improper handling of ES3 commands. An attacker can
    exploit this flaw to disclose memory contents.
    (CVE-2015-1240)

  - An unspecified tap-jacking flaw exists when certain tap
    events aren't preceded by TapDown events. An attacker
    can exploit this to direct taps to cross-pages and
    cross-domains. (CVE-2015-1241)

  - A type confusion error exists in the
    ReduceTransitionElementsKind() function in
    hydrogen-check-elimination.cc. An attacker can exploit
    this error to execute arbitrary code. (CVE-2015-1242)

  - A flaw exists related to WebSocket connections due to
    HTTP Strict Transport Security (HSTS) not being strictly
    enforced. A man-in-the-middle attacker can exploit this
    flaw to view and manipulate protected communication.
    (CVE-2015-1244)

  - A use-after-free error exists in
    open_pdf_in_reader_view.cc due to improper handling
    handling the 'Open PDF in Reader' bubble on navigations.
    An attacker can exploit this flaw to dereference already
    freed memory and execute arbitrary code. (CVE-2015-1245)

  - An unspecified out-of-bounds read flaw exists in Blink.
    An attacker can exploit this to disclose memory
    contents. (CVE-2015-1246)

  - A flaw exists in the OnPageHasOSDD() function in
    search_engine_tab_helper.cc due to improper handling
    of URLs for the OpenSearch descriptor. An attacker can
    exploit this flaw to disclose sensitive information.
    (CVE-2015-1247)

  - An unspecified flaw exists that allows an attacker to
    bypass SafeBrowsing. (CVE-2015-1248)

  - Multiple unspecified vulnerabilities exist that allow an
    attacker to have an unspecified impact. (CVE-2015-1249)

  - Multiple unspecified vulnerabilities exist in V8 that
    allow an attacker to cause a denial of service and
    other unspecified impacts.
    (CVE-2015-3333)

  - A media permission handling weakness exists due to
    camera and microphone permissions being merged into a
    single 'Media' permission. An attacker can exploit this,
    via a specially crafted website, to turn on a victim's
    camera while the victim believes camera access is
    prohibited. (CVE-2015-3334)

  - A flaw exists due to missing address space usage
    limitation (RLIMIT_AS and RLIMIT_DATA) in the Native
    Client (NaCl) process. This allows a remote attacker to
    run a crafted program in the NaCl sandbox and to conduct
    row-hammer attacks. (CVE-2015-3335)
    
Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://googlechromereleases.blogspot.com/2015/04/stable-channel-update_14.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72311cf0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 42.0.2311.90 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'42.0.2311.90', severity:SECURITY_HOLE);

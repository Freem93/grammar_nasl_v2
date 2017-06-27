#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83746);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id(
    "CVE-2015-1251",
    "CVE-2015-1252",
    "CVE-2015-1253",
    "CVE-2015-1254",
    "CVE-2015-1255",
    "CVE-2015-1256",
    "CVE-2015-1257",
    "CVE-2015-1258",
    "CVE-2015-1259",
    "CVE-2015-1260",
    "CVE-2015-1262",
    "CVE-2015-1263",
    "CVE-2015-1264",
    "CVE-2015-1265"
  );
  script_bugtraq_id(
    74723,
    74727
  );
  script_osvdb_id(
    122287,
    122288,
    122289,
    122290,
    122291,
    122292,
    122293,
    122294,
    122295,
    122296,
    122297,
    122299,
    122300,
    122330
  );

  script_name(english:"Google Chrome < 43.0.2357.65 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 43.0.2357.65. It is, therefore, affected by multiple
vulnerabilities :

  - A Use-after-free memory error exists in the
    SpeechRecognitionClient implementation that allows
    remote attackers, using a crafted document, to execute
    arbitrary code. (CVE-2015-1251)

  - The Write() and DoWrite() methods of the class
    PartialCircularBuffer do not properly handle wraps.
    A remote attacker, by using write operations with a
    large amount of data, can exploit this to bypass the
    sandbox protection or cause a denial of service.
    (CVE-2015-1252)

  - The DOM implementation in Blink does not properly
    handle SCRIPT elements during adjustment of DOM node
    locations. A remote attacker, using crafted JavaScript
    code that appends a child to a SCRIPT element, can
    exploit this flaw to bypass the same origin policy.
    (CVE-2015-1253)

  - The 'core/dom/Document.cpp' in Blink enables the
    inheritance of the 'designMode' attribute. A remote
    attacker, using a crafted web page, can utilize this to
    bypass the same origin policy via the availability of
    editing. (CVE-2015-1254)

  - A use-after-free memory error exists in the WebAudio
    implementation when handling the stop action for an
    audio track. A remote attacker can exploit this to
    cause a denial of service or possibly execute
    arbitrary code. (CVE-2015-1255)

  - A use-after-free memory error exists in the SVG
    implementation in Blink, related to the improper
    handling of a shadow tree for a use element. A remote
    attacker, using a crafted document, can exploit this
    to cause a denial of service or possibly execute
    arbitrary code. (CVE-2015-1256)

  - The SVG implementation in Blink does not properly handle
    an insufficient number of values in an feColorMatrix
    filter. A remote attacker, using a crafted document, can
    exploit this to cause a denial of service via a
    container overflow. (CVE-2015-1257)

  - The libvpx library code was not compiled with an
    appropriate '--size-limit' value. This allows a remote
    attacker, using a crafted frame size in VP9 video data,
    to trigger a negative value for a size field, thus
    causing a denial of service or possibly having other
    impact. (CVE-2015-1258)

  - Google PDFium does not properly initialize memory. A
    remote attacker can exploit this to cause a denial of
    service or possibly have other unspecified impact.
    (CVE-2015-1259)

  - Multiple use-after-free memory errors exist the WebRTC
    implementation. A remote attacker can exploit these, by
    using a crafted JavaScript code that executes upon
    completion of a getUserMedia request, to cause a denial
    of service or possibly have other unspecified impact.
    (CVE-2015-1260)

  - The file 'HarfBuzzShaper.cpp' in Blink does not properly
    initialize a certain width field. A remote attacker,
    using crafted Unicode text, can exploit this to cause a
    denial of service or have other unspecified impact.
    (CVE-2015-1262)

  - The Spellcheck API implementation does not use an HTTPS
    session for downloading a Hunspell dictionary. A
    man-in-the-middle attacker, using a crafted file, can
    exploit this flaw to deliver incorrect spelling
    suggestions or possibly have other unspecified impact.
    (CVE-2015-1263)

  - A cross-site scripting (XSS) vulnerability exists that
    is related to the Bookmarks feature. A remote attacker,
    using crafted data, can exploit this to inject arbitrary
    web script or HTML. (CVE-2015-1264)

  - Multiple unspecified vulnerabilities exist that allow an
    attacker to cause a denial of service or possibly have
    other impact via unknown vectors. (CVE-2015-1265)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://googlechromereleases.blogspot.com/2015/05/stable-channel-update_19.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9eefd81");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 43.0.2357.65 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/21");

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

google_chrome_check_version(fix:'43.0.2357.65', severity:SECURITY_HOLE, xss:TRUE);

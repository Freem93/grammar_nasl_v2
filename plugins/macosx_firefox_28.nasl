#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73096);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/20 14:12:04 $");

  script_cve_id(
    "CVE-2014-1493",
    "CVE-2014-1494",
    "CVE-2014-1496",
    "CVE-2014-1497",
    "CVE-2014-1498",
    "CVE-2014-1499",
    "CVE-2014-1500",
    "CVE-2014-1502",
    "CVE-2014-1504",
    "CVE-2014-1505",
    "CVE-2014-1508",
    "CVE-2014-1509",
    "CVE-2014-1510",
    "CVE-2014-1511",
    "CVE-2014-1512",
    "CVE-2014-1513",
    "CVE-2014-1514"
  );
  script_bugtraq_id(
    66203,
    66206,
    66207,
    66209,
    66240,
    66412,
    66416,
    66417,
    66418,
    66419,
    66421,
    66422,
    66423,
    66425,
    66426,
    66428,
    66429
  );
  script_osvdb_id(
    103268,
    104590,
    104591,
    104592,
    104593,
    104594,
    104621,
    104622,
    104625,
    104626,
    104627,
    104628,
    104629,
    104630,
    104631,
    104632,
    104656
  );

  script_name(english:"Firefox < 28.0 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox is a version prior to version 28.0.
It is, therefore, potentially affected by multiple vulnerabilities :

  - Memory issues exist that could lead to arbitrary code
    execution. (CVE-2014-1493, CVE-2014-1494)

  - An issue exists where extracted files for updates are
    not read-only while updating.  An attacker may be able
    to modify these extracted files resulting in privilege
    escalation. (CVE-2014-1496)

  - An out-of-bounds read error exists when decoding WAV
    format audio files that could lead to a denial of
    service attack or information disclosure.
    (CVE-2014-1497)

  - An issue exists in the 'crypto.generateCRFMRequest'
    method due to improper validation of the KeyParams
    argument when generating 'ec-dual-use' requests.  This
    could lead to a denial of service attack.
    (CVE-2014-1498)

  - An issue exists that could allow for spoofing attacks to
    occur during a WebRTC session.  Exploitation of this
    issue could allow an attacker to gain access to the
    user's webcam or microphone. (CVE-2014-1499)

  - An issue exists with JavaScript 'onbeforeunload' events
    that could lead to denial of service attacks.
    (CVE-2014-1500)

  - An issue exists where WebGL context from one website
    can be injected into the WebGL context of another
    website, which could result in arbitrary content being
    rendered from the second website. (CVE-2014-1502)

  - A cross-site scripting issue exists due to the Content
    Security Policy (CSP) of 'data:' documents not being
    saved for a session restore.  Under certain
    circumstances, an attacker may be able to evade the CSP
    of a remote website resulting in a cross-scripting
    attack. (CVE-2014-1504)

  - An out-of-bounds read error exists when polygons are
    rendered in 'MathML' that could lead to information
    disclosure. (CVE-2014-1508)

  - A memory corruption issue exists in the Cairo graphics
    library when rendering a PDF file that could lead to
    arbitrary code execution or a denial of service attack.
    (CVE-2014-1509)

  - An issue exists in the SVG filters and the
    feDisplacementMap element that could lead to
    information disclosure via timing attacks.
    (CVE-2014-1505)

  - An issue exists that could allow malicious websites to
    load chrome-privileged pages when JavaScript
    implemented WebIDL calls the 'window.open()' function,
    which may result in arbitrary code execution.
    (CVE-2014-1510)

  - An issue exists that could allow a malicious website to
    bypass the pop-up blocker. (CVE-2014-1511)

  - A use-after-free memory issue exists in 'TypeObjects'
    in the JavaScript engine during Garbage Collection
    that could lead to arbitrary code execution.
    (CVE-2014-1512)

  - An out-of-bounds write error exists due to
    'TypedArrayObject' improperly handling 'ArrayBuffer'
    objects that could result in arbitrary code execution.
    (CVE-2014-1513)

  - An out-of-bounds write error exists when copying values
    from one array to another that could result in arbitrary
    code execution. (CVE-2014-1514)");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/531617/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-15.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-16.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-17.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-18.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-19.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-15.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-16.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-17.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-18.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-19.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-20.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-22.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-23.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-26.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-27.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-28.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-29.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-30.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-31.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-32.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 28.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox WebIDL Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'28.0', severity:SECURITY_HOLE, xss:TRUE);

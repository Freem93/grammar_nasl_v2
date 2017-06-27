#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92755);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id(
    "CVE-2016-0718",
    "CVE-2016-2830",
    "CVE-2016-2835",
    "CVE-2016-2836",
    "CVE-2016-2837",
    "CVE-2016-2838",
    "CVE-2016-5250",
    "CVE-2016-5251",
    "CVE-2016-5252",
    "CVE-2016-5253",
    "CVE-2016-5254",
    "CVE-2016-5255",
    "CVE-2016-5258",
    "CVE-2016-5259",
    "CVE-2016-5260",
    "CVE-2016-5261",
    "CVE-2016-5262",
    "CVE-2016-5263",
    "CVE-2016-5264",
    "CVE-2016-5265",
    "CVE-2016-5266",
    "CVE-2016-5268"
  );
  script_bugtraq_id(
    90729,
    92258,
    92260,
    92261
  );
  script_osvdb_id(
    138680,
    142419,
    142420,
    142421,
    142422,
    142423,
    142424,
    142425,
    142426,
    142427,
    142428,
    142429,
    142430,
    142431,
    142432,
    142433,
    142434,
    142435,
    142468,
    142469,
    142471,
    142472,
    142473,
    142474,
    142475,
    142476,
    142477,
    142478,
    142479,
    142480,
    142481,
    142482,
    142484,
    142485,
    142486,
    142487,
    142488,
    142603,
    142607,
    142608,
    142609
  );
  script_xref(name:"MFSA", value:"2016-62");
  script_xref(name:"MFSA", value:"2016-63");
  script_xref(name:"MFSA", value:"2016-64");
  script_xref(name:"MFSA", value:"2016-66");
  script_xref(name:"MFSA", value:"2016-67");
  script_xref(name:"MFSA", value:"2016-68");
  script_xref(name:"MFSA", value:"2016-69");
  script_xref(name:"MFSA", value:"2016-70");
  script_xref(name:"MFSA", value:"2016-71");
  script_xref(name:"MFSA", value:"2016-72");
  script_xref(name:"MFSA", value:"2016-73");
  script_xref(name:"MFSA", value:"2016-74");
  script_xref(name:"MFSA", value:"2016-75");
  script_xref(name:"MFSA", value:"2016-76");
  script_xref(name:"MFSA", value:"2016-77");
  script_xref(name:"MFSA", value:"2016-78");
  script_xref(name:"MFSA", value:"2016-79");
  script_xref(name:"MFSA", value:"2016-80");
  script_xref(name:"MFSA", value:"2016-81");
  script_xref(name:"MFSA", value:"2016-83");
  script_xref(name:"MFSA", value:"2016-84");

  script_name(english:"Firefox < 48 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior
to 48. It is, therefore, affected by multiple vulnerabilities :

  - An overflow condition exists in the expat XML parser due
    to improper validation of user-supplied input when
    handling malformed input documents. An attacker can
    exploit this to cause a buffer overflow, resulting in a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-0718)

  - An information disclosure vulnerability exists due to a
    failure to close connections after requesting favicons.
    An attacker can exploit this to continue to send
    requests to the user's browser and disclose sensitive
    information.(CVE-2016-2830)

  - Multiple memory corruption issues exist due to improper
    validation of user-supplied input. An attacker can
    exploit these issues to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-2835, CVE-2016-2836)

  - An overflow condition exists in the ClearKey Content
    Decryption Module (CDM) used by the Encrypted Media
    Extensions (EME) API due to improper validation of
    user-supplied input. An attacker can exploit this to
    cause a buffer overflow, resulting in a denial of
    service condition or the execution of arbitrary code.
    (CVE-2016-2837)

  - An overflow condition exists in the ProcessPDI()
    function in layout/base/nsBidi.cpp due to improper
    validation of user-supplied input. An attacker can
    exploit this to cause a heap-based buffer overflow,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2016-2838)

  - A flaw exists in the Resource Timing API during page
    navigation. An attacker can exploit this to disclose
    sensitive information. (CVE-2016-5250)

  - A flaw exists that is triggered when decoding
    url-encoded values in 'data:' URLs. An attacker can
    exploit this, via non-ASCII or emoji characters, to
    spoof the address in the address bar. (CVE-2016-5251)

  - An underflow condition exists in the BasePoint4d()
    function in gfx/2d/Matrix.h due to improper validation
    of user-supplied input when calculating clipping regions
    in 2D graphics. A remote attacker can exploit this to
    cause a stack-based buffer underflow, resulting in a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-5252)

  - A flaw in the updater service exists when launched using
    the callback application path parameter that allows an
    attacker to escalate privileges. (CVE-2016-5253)

  - A use-after-free error exists in the KeyDown() function
    in layout/xul/nsXULPopupManager.cpp when using the alt
    key in conjunction with top level menu items. An
    attacker can exploit this to dereference already freed
    memory, resulting in a denial of service condition or
    the execution of arbitrary code. (CVE-2016-5254)

  - A use-after-free error exists in the sweep() function
    that is triggered when handling objects and pointers
    during incremental garbage collection. An attacker can
    exploit this to dereference already freed memory,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2016-5255)

  - A use-after-free error exists in WebRTC that is
    triggered when handling DTLS objects. An attacker can
    exploit this to dereference already freed memory,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2016-5258)

  - A use-after-free error exists in the DestroySyncLoop()
    function in dom/workers/WorkerPrivate.cpp that is
    triggered when handling nested sync event loops in
    Service Workers. An attacker can exploit this to
    dereference already freed memory, resulting in a denial
    of service condition or the execution of arbitrary code.
    (CVE-2016-5259)

  - An information disclosure vulnerability exists in the
    restorableFormNodes() function in XPathGenerator.jsm due
    to persistently storing passwords in plaintext in
    session restore data. An attacker can exploit this to
    disclose password information. (CVE-2016-5260)

  - An integer overflow condition exists in the
    ProcessInput() function in WebSocketChannel.cpp due to
    improper validation of user-supplied input when handling
    specially crafted WebSocketChannel packets. An attacker
    can exploit this to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2016-5261)

  - A security bypass vulnerability exists due to event
    handler attributes on a <marquee> tag being executed
    inside a sandboxed iframe that does not have the
    allow-scripts flag set. An attacker can exploit this to
    bypass cross-site scripting protection mechanisms.
    (CVE-2016-5262)

  - A type confusion flaw exists in the HitTest() function
    in nsDisplayList.cpp when handling display
    transformations. An attacker can exploit this to execute
    arbitrary code. (CVE-2016-5263)

  - A use-after-free error exists in the
    NativeAnonymousChildListChange() function when applying
    effects to SVG elements. An attacker can exploit this to
    dereference already freed memory, resulting in a denial
    of service condition or the execution of arbitrary code.
    (CVE-2016-5264)

  - A flaw exists in the Redirect() function in
    nsBaseChannel.cpp that is triggered when a malicious 
    shortcut is called from the same directory as a local
    HTML file. An attacker can exploit this to bypass the
    same-origin policy. (CVE-2016-5265)

  - A flaw exists due to a failure to properly filter file
    URIs dragged from a web page to a different piece of
    software. An attacker can exploit this to disclose
    sensitive information. (CVE-2016-5266)

  - A flaw exists that is triggered when handling certain
    specific 'about:' URLs that allows an attacker to spoof
    the contents of system information or error messages
    (CVE-2016-5268)

  - A flaw exists in woff2 that is triggered during the
    handling of TTC detection. An attacker can exploit this
    to have an unspecified impact. (VulnDB 142603)

  - Multiple unspecified flaws exist in woff2 that allow an
    attacker to cause a denial of service condition. (VulnDB
    142607, 142608, and 142609)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-62/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-63/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-64/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-66/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-67/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-68/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-69/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-70/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-71/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-72/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-73/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-74/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-75/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-76/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-77/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-78/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-79/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-80/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-81/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-83/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-84/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox version 48 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'48', severity:SECURITY_HOLE, xss:TRUE);

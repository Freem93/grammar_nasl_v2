#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92754);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id(
    "CVE-2016-2830",
    "CVE-2016-2835",
    "CVE-2016-2836",
    "CVE-2016-2837",
    "CVE-2016-2838",
    "CVE-2016-5252",
    "CVE-2016-5254",
    "CVE-2016-5258",
    "CVE-2016-5259",
    "CVE-2016-5262",
    "CVE-2016-5263",
    "CVE-2016-5264",
    "CVE-2016-5265"
  );
  script_bugtraq_id(
    92258,
    92261
  );
  script_osvdb_id(
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
    142474,
    142476,
    142478,
    142479,
    142480,
    142481,
    142482,
    142484,
    142485,
    142486
  );
  script_xref(name:"MFSA", value:"2016-62");
  script_xref(name:"MFSA", value:"2016-63");
  script_xref(name:"MFSA", value:"2016-64");
  script_xref(name:"MFSA", value:"2016-67");
  script_xref(name:"MFSA", value:"2016-68");
  script_xref(name:"MFSA", value:"2016-70");
  script_xref(name:"MFSA", value:"2016-72");
  script_xref(name:"MFSA", value:"2016-73");
  script_xref(name:"MFSA", value:"2016-76");
  script_xref(name:"MFSA", value:"2016-77");
  script_xref(name:"MFSA", value:"2016-78");
  script_xref(name:"MFSA", value:"2016-79");
  script_xref(name:"MFSA", value:"2016-80");

  script_name(english:"Firefox ESR 45.x < 45.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is
45.x prior to 45.3. It is, therefore, affected by multiple
vulnerabilities :

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

  - An underflow condition exists in the BasePoint4d()
    function in gfx/2d/Matrix.h due to improper validation
    of user-supplied input when calculating clipping regions
    in 2D graphics. A remote attacker can exploit this to
    cause a stack-based buffer underflow, resulting in a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-5252)

  - A use-after-free error exists in the KeyDown() function
    in layout/xul/nsXULPopupManager.cpp when using the alt
    key in conjunction with top level menu items. An
    attacker can exploit this to dereference already freed
    memory, resulting in a denial of service condition or
    the execution of arbitrary code. (CVE-2016-5254)

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
    same-origin policy. (CVE-2016-5265)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-62/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-63/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-64/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-67/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-68/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-70/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-72/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-73/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-76/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-77/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-78/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-79/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-80/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox ESR version 45.3 or later.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
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

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'45.3', min:'45.0', severity:SECURITY_HOLE, xss:TRUE);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97639);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/03/24 14:10:48 $");

  script_cve_id(
    "CVE-2017-5398",
    "CVE-2017-5399",
    "CVE-2017-5400",
    "CVE-2017-5401",
    "CVE-2017-5402",
    "CVE-2017-5403",
    "CVE-2017-5404",
    "CVE-2017-5405",
    "CVE-2017-5406",
    "CVE-2017-5407",
    "CVE-2017-5408",
    "CVE-2017-5409",
    "CVE-2017-5410",
    "CVE-2017-5411",
    "CVE-2017-5412",
    "CVE-2017-5413",
    "CVE-2017-5414",
    "CVE-2017-5415",
    "CVE-2017-5416",
    "CVE-2017-5417",
    "CVE-2017-5418",
    "CVE-2017-5419",
    "CVE-2017-5420",
    "CVE-2017-5421",
    "CVE-2017-5422",
    "CVE-2017-5427"
  );
  script_bugtraq_id(
    96651,
    96654,
    96664,
    96677,
    96691,
    96692,
    96693,
    96696
  );
  script_osvdb_id(
    144079,
    147374,
    153143,
    153144,
    153145,
    153146,
    153147,
    153148,
    153149,
    153150,
    153151,
    153152,
    153153,
    153154,
    153155,
    153156,
    153157,
    153158,
    153159,
    153160,
    153161,
    153162,
    153163,
    153164,
    153165,
    153166,
    153167,
    153168,
    153169,
    153170,
    153171,
    153172,
    153173,
    153174,
    153175,
    153176,
    153177,
    153178,
    153179,
    153180,
    153181,
    153182,
    153183,
    153189,
    153190,
    153191,
    153192,
    153193,
    153194,
    153195,
    153196,
    153198,
    153203,
    153204,
    153205,
    153206,
    153207,
    153209,
    153211,
    153212,
    153213,
    153214,
    153215,
    153217,
    153248,
    153249
  );
  script_xref(name:"MFSA", value:"2017-05");

  script_name(english:"Mozilla Firefox < 52.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote Windows host is
prior to 52.0. It is, therefore, affected by multiple
vulnerabilities :

  - Mozilla developers and community members Boris Zbarsky,
    Christian Holler, Honza Bambas, Jon Coppeard, Randell
    Jesup, Andre Bargull, Kan-Ru Chen, and Nathan Froyd
    reported memory safety bugs present in Firefox 51 and
    Firefox ESR 45.7. Some of these bugs showed evidence of
    memory corruption and we presume that with enough
    effort that some of these could be exploited to run
    arbitrary code. (CVE-2017-5398)

  - Mozilla developers and community members Carsten Book,
    Calixte Denizet, Christian Holler, Andrew McCreight,
    David Bolter, David Keeler, Jon Coppeard, Tyson Smith,
    Ronald Crane, Tooru Fujisawa, Ben Kelly, Bob Owen, Jed
    Davis, Julian Seward, Julian Hector, Philipp, Markus
    Stange, and Andre Bargull reported memory safety bugs
    present in Firefox 51. Some of these bugs showed
    evidence of memory corruption and we presume that with
    enough effort that some of these could be exploited to
    run arbitrary code. (CVE-2017-5399)

  - JIT-spray targeting asm.js combined with a heap spray
    allows for a bypass of ASLR and DEP protections leading
    to potential memory corruption attacks. (CVE-2017-5400)

  - A crash triggerable by web content in which an
    ErrorResult references unassigned memory due to a logic
    error. The resulting crash may be exploitable.
    (CVE-2017-5401)

  - A use-after-free can occur when events are fired for a
    FontFace object after the object has been already been
    destroyed while working with fonts. This results in a
    potentially exploitable crash. (CVE-2017-5402)

  - When adding a range to an object in the DOM, it is
    possible to use addRange to add the range to an
    incorrect root object. This triggers a use-after-free,
    resulting in a potentially exploitable crash.
    (CVE-2017-5403)

  - A use-after-free error can occur when manipulating
    ranges in selections with one node inside a native
    anonymous tree and one node outside of it. This results
    in a potentially exploitable crash. (CVE-2017-5404)

  - Certain response codes in FTP connections can result in
    the use of uninitialized values for ports in FTP
    operations. (CVE-2017-5405)

  - A segmentation fault can occur in the Skia graphics
    library during some canvas operations due to issues
    with mask/clip intersection and empty masks.
    (CVE-2017-5406)

  - Using SVG filters that don't use the fixed point math
    implementation on a target iframe, a malicious page can
    extract pixel values from a targeted user. This can be
    used to extract history information and read text
    values across domains. This violates same-origin policy
    and leads to information disclosure. (CVE-2017-5407)

  - Video files loaded video captions cross-origin without
    checking for the presence of CORS headers permitting
    such cross-origin use, leading to potential information
    disclosure for video captions. (CVE-2017-5408)

  - The Mozilla Windows updater can be called by a
    non-privileged user to delete an arbitrary local file
    by passing a special path to the callback parameter
    through the Mozilla Maintenance Service, which has
    privileged access. Note: This attack requires local
    system access and only affects Windows. Other operating
    systems are not affected. (CVE-2017-5409)

  - Memory corruption resulting in a potentially
    exploitable crash during garbage collection of
    JavaScript due errors in how incremental sweeping is
    managed for memory cleanup. (CVE-2017-5410)

  - A use-after-free can occur during buffer storage
    operations within the ANGLE graphics library, used for
    WebGL content. The buffer storage can be freed while
    still in use in some circumstances, leading to a
    potentially exploitable crash. Note: This issue is in
    libGLES, which is only in use on Windows. Other
    operating systems are not affected. (CVE-2017-5411)

  - A buffer overflow read during SVG filter color value
    operations, resulting in data exposure. (CVE-2017-5412)

  - A segmentation fault can occur during some
    bidirectional layout operations. (CVE-2017-5413)

  - The file picker dialog can choose and display the wrong
    local default directory when instantiated. On some
    operating systems, this can lead to information
    disclosure, such as the operating system or the local
    account name. (CVE-2017-5414)

  - An attack can use a blob URL and script to spoof an
    arbitrary addressbar URL prefaced by blob: as the
    protocol, leading to user confusion and further
    spoofing attacks. (CVE-2017-5415)

  - In certain circumstances a networking event listener
    can be prematurely released. This appears to result in
    a null dereference in practice. (CVE-2017-5416)

  - When dragging content from the primary browser pane to
    the addressbar on a malicious site, it is possible to
    change the addressbar so that the displayed location
    following navigation does not match the URL of the
    newly loaded page. This allows for spoofing attacks.
    (CVE-2017-5417)

  - An out of bounds read error occurs when parsing some
    HTTP digest authorization responses, resulting in
    information leakage through the reading of random
    memory containing matches to specifically set patterns.
    (CVE-2017-5418)

  - If a malicious site repeatedly triggers a modal
    authentication prompt, eventually the browser UI will
    become non-responsive, requiring shutdown through the
    operating system. This is a denial of service (DOS)
    attack. (CVE-2017-5419)

  - A javascript: url loaded by a malicious page can
    obfuscate its location by blanking the URL displayed in
    the addressbar, allowing for an attacker to spoof an
    existing page without the malicious page's address
    being displayed correctly. (CVE-2017-5420)

  - A malicious site could spoof the contents of the print
    preview window if popup windows are enabled, resulting
    in user confusion of what site is currently loaded.
    (CVE-2017-5421)

  - If a malicious site uses the view-source: protocol in a
    series within a single hyperlink, it can trigger a
    non-exploitable browser crash when the hyperlink is
    selected. This was fixed by no longer making
    view-source: linkable. (CVE-2017-5422)

  - A non-existent chrome.manifest file will attempt to be
    loaded during startup from the primary installation
    directory. If a malicious user with local access puts
    chrome.manifest and other referenced files in this
    directory, they will be loaded and activated during
    startup. This could result in malicious software being
    added without consent or modification of referenced
    installed files. (CVE-2017-5427)

Note that Tenable Network Security has extracted the preceding
description block directly from the Mozilla security advisories.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-05/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 52.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:R");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', fix:'52.0', severity:SECURITY_HOLE);

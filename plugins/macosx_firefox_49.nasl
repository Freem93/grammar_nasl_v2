#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93660);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2016-2827",
    "CVE-2016-5256",
    "CVE-2016-5257",
    "CVE-2016-5270",
    "CVE-2016-5271",
    "CVE-2016-5272",
    "CVE-2016-5273",
    "CVE-2016-5274",
    "CVE-2016-5275",
    "CVE-2016-5276",
    "CVE-2016-5277",
    "CVE-2016-5278",
    "CVE-2016-5279",
    "CVE-2016-5280",
    "CVE-2016-5281",
    "CVE-2016-5282",
    "CVE-2016-5283",
    "CVE-2016-5284"
  );
  script_bugtraq_id(
    93049,
    93052
  );
  script_osvdb_id(
    144426,
    144608,
    144609,
    144610,
    144611,
    144612,
    144613,
    144614,
    144615,
    144616,
    144617,
    144618,
    144619,
    144620,
    144621,
    144622,
    144623,
    144624,
    144625,
    144626,
    144627,
    144628,
    144629,
    144630,
    144631,
    144632,
    144633,
    144634,
    144635,
    144636,
    144637,
    144638
  );
  script_xref(name:"MFSA", value:"2016-85");

  script_name(english:"Mozilla Firefox < 49.0 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote Mac OS X host
is prior to 49.0. It is, therefore, affected by multiple
vulnerabilities :

  - An out-of-bounds read error exists within file
    dom/security/nsCSPParser.cpp when handling content
    security policies (CSP) containing empty referrer
    directives. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition.
    (CVE-2016-2827)

  - Multiple memory safety issues exist that allow an
    unauthenticated, remote attacker to potentially execute
    arbitrary code. (CVE-2016-5256, CVE-2016-5257)

  - A heap buffer overflow condition exists in the
    nsCaseTransformTextRunFactory::TransformString()
    function in layout/generic/nsTextRunTransformations.cpp
    when converting text containing certain Unicode
    characters. An unauthenticated, remote attacker can
    exploit this to execute arbitrary code. (CVE-2016-5270)

  - An out-of-bounds read error exists in the
    nsCSSFrameConstructor::GetInsertionPrevSibling()
    function in file layout/base/nsCSSFrameConstructor.cpp
    when handling text runs. An unauthenticated, remote
    attacker can exploit this to disclose memory contents.
    (CVE-2016-5271)

  - A type confusion error exists within file
    layout/forms/nsRangeFrame.cpp when handling layout with
    input elements. An unauthenticated, remote attacker can
    exploit this to execute arbitrary code. (CVE-2016-5272)

  - An unspecified flaw exists in the
    HyperTextAccessible::GetChildOffset() function that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2016-5273)

  - A use-after-free error exists within file
    layout/style/nsRuleNode.cpp when handling web animations
    during restyling. An unauthenticated, remote attacker
    can exploit this to execute arbitrary code.
    (CVE-2016-5274)

  - A buffer overflow condition exists in the
    FilterSupport::ComputeSourceNeededRegions() function
    when handling empty filters during canvas rendering. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-5275)

  - A use-after-free error exists in the
    DocAccessible::ProcessInvalidationList() function within
    file accessible/generic/DocAccessible.cpp when setting
    an aria-owns attribute. An unauthenticated, remote
    attacker can exploit this to execute arbitrary code.
    (CVE-2016-5276)

  - A use-after-free error exists in the
    nsRefreshDriver::Tick() function when handling web
    animations destroying a timeline. An unauthenticated,
    remote attacker can exploit this to execute arbitrary
    code. (CVE-2016-5277)

  - A buffer overflow condition exists in the
    nsBMPEncoder::AddImageFrame() function within file
    dom/base/ImageEncoder.cpp when encoding image frames to
    images. An unauthenticated, remote attacker can exploit
    this to execute arbitrary code. (CVE-2016-5278)

  - A flaw exists that is triggered when handling
    drag-and-drop events for files. An unauthenticated,
    remote attacker can exploit this disclose the full local
    file path. (CVE-2016-5279)

  - A use-after-free error exists in the
    nsTextNodeDirectionalityMap::RemoveElementFromMap()
    function within file dom/base/DirectionalityUtils.cpp
    when handling changing of text direction. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-5280)

  - A use-after-free error exists when handling SVG format
    content that is being manipulated through script code.
    An unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-5281)

  - A flaw exists when handling content that requests
    favicons from non-whitelisted schemes that are using
    certain URI handlers. An unauthenticated, remote
    attacker can exploit this to bypass intended
    restrictions. (CVE-2016-5282)

  - A flaw exists that is related to the handling of iframes
    that allow an unauthenticated, remote attacker to
    conduct an 'iframe src' fragment timing attack,
    resulting in disclosure of cross-origin data.
    (CVE-2016-5283)

  - A flaw exists due to the certificate pinning policy for
    built-in sites (e.g., addons.mozilla.org) not being
    honored when pins have expired. A man-in-the-middle
    (MitM) attacker can exploit this to generate a trusted
    certificate, which could be used to conduct spoofing
    attacks. (CVE-2016-5284)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-85/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 49.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'49', severity:SECURITY_HOLE);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87473);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/01/31 05:42:28 $");

  script_cve_id(
    "CVE-2015-7201",
    "CVE-2015-7205",
    "CVE-2015-7210",
    "CVE-2015-7212",
    "CVE-2015-7213",
    "CVE-2015-7214",
    "CVE-2015-7222"
  );
  script_bugtraq_id(
    79279,
    79283
  );
  script_osvdb_id(
    125392,
    131857,
    131858,
    131860,
    131863,
    131864,
    131866,
    131868,
    131870
  );

  script_name(english:"Firefox ESR < 38.5 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Mac OS X host is
prior to 38.5. It is, therefore, affected by the following
vulnerabilities :

  - Multiple unspecified memory corruption issues exist due
    to improper validation of user-supplied input. A remote
    attacker can exploit these issues by convincing a user
    to visit a specially crafted web page, resulting in the
    execution of arbitrary code. (CVE-2015-7201)

  - A flaw exists in the RtpHeaderParser::Parse() function
    due to improper handling of RTP headers. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted RTP headers, to execute arbitrary
    code. (CVE-2015-7205)

  - A use-after-free error exists due to improper prevention
    of datachannel operations on closed PeerConnections. An
    attacker can exploit this to dereference already freed
    memory, resulting in the execution of arbitrary code.
    (CVE-2015-7210)

  - An overflow condition exists in the AllocateForSurface()
    function due to improper validation of user-supplied
    input when handling texture allocation in graphics
    operations. An attacker can exploit this to execute
    arbitrary code. (CVE-2015-7212)

  - An integer overflow condition exists in the
    readMetaData() function due to improper validation of
    user-supplied input when handling a specially crafted
    MP4 file. An attacker can exploit this to execute
    arbitrary code. (CVE-2015-7213)

  - A same-origin bypass vulnerability exists due to
    improper handling of 'data:' and 'view-source:' URIs. An
    attacker can exploit this to read data from cross-site
    URLs and local files. (CVE-2015-7214)

  - An integer underflow condition exists in the bundled
    version of libstagefright in the parseChunk() function
    that is triggered when handling 'covr' chunks. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted media content, to crash the
    application or execute arbitrary code. (CVE-2015-7222)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-138/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-139/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-145/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-146/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-147/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-149/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox ESR 38.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

is_esr = get_kb_item(kb_base+"/is_esr");
if (isnull(is_esr)) audit(AUDIT_NOT_INST, "Mozilla Firefox ESR");

mozilla_check_version(product:'firefox', version:version, path:path, esr:TRUE, fix:'38.5', severity:SECURITY_HOLE);

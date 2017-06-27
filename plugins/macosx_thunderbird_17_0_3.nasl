#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64720);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id(
    "CVE-2013-0765",
    "CVE-2013-0772",
    "CVE-2013-0773",
    "CVE-2013-0774",
    "CVE-2013-0775",
    "CVE-2013-0776",
    "CVE-2013-0777",
    "CVE-2013-0778",
    "CVE-2013-0779",
    "CVE-2013-0780",
    "CVE-2013-0781",
    "CVE-2013-0782",
    "CVE-2013-0783",
    "CVE-2013-0784"
  );
  script_bugtraq_id(
    58034,
    58036,
    58037,
    58038,
    58040,
    58041,
    58042,
    58043,
    58044,
    58047,
    58048,
    58049,
    58050,
    58051
  );
  script_osvdb_id(
    90418,
    90419,
    90420,
    90421,
    90422,
    90423,
    90424,
    90425,
    90426,
    90427,
    90428,
    90429,
    90430,
    90431
  );

  script_name(english:"Thunderbird < 17.0.3 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a mail client that is potentially
affected by several vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Thunderbird is earlier than 17.0.3 and thus,
is potentially affected by the following security issues :

  - Numerous memory safety errors exist. (CVE-2013-0783,
    CVE-2013-0784)

  - An out-of-bounds read error exists related to the
    handling of GIF images. (CVE-2013-0772)

  - An error exists related to 'WebIDL' object wrapping
    that has an unspecified impact. (CVE-2013-0765)

  - An error exists related to Chrome Object Wrappers (COW)
    or System Only Wrappers (SOW) that could allow security
    bypass. (CVE-2013-0773)

  - The file system location of the active browser profile
    could be disclosed and used in further attacks.
    (CVE-2013-0774)

  - A use-after-free error exists in the function
    'nsImageLoadingContent'. (CVE-2013-0775)

  - Spoofing HTTPS URLs is possible due to an error related
    to proxy '407' responses and embedded script code.
    (CVE-2013-0776)

  - A heap-based use-after-free error exists in the function
    'nsDisplayBoxShadowOuter::Paint'. (CVE-2013-0777)

  - An out-of-bounds read error exists in the function
    'ClusterIterator::NextCluster'. (CVE-2013-0778)

  - An out-of-bounds read error exists in the function
    'nsCodingStateMachine::NextState'. (CVE-2013-0779)

  - A heap-based use-after-free error exists in the function
    'nsOverflowContinuationTracker::Finish'. (CVE-2013-0780)

  - A heap-based use-after-free error exists in the function
    'nsPrintEngine::CommonPrint'. (CVE-2013-0781)

  - A heap-based buffer overflow error exists in the
    function 'nsSaveAsCharset::DoCharsetConversion'.
    (CVE-2013-0782)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-21.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-22.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-23.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-24.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-25.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-26.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-27.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-28.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 17.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include("mozilla_version.inc");
kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Thunderbird install is in the ESR branch.');

mozilla_check_version(product:'thunderbird', version:version, path:path, esr:FALSE, fix:'17.0.3', severity:SECURITY_HOLE);
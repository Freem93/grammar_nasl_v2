#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73770);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id(
    "CVE-2014-1518",
    "CVE-2014-1519",
    "CVE-2014-1523",
    "CVE-2014-1524",
    "CVE-2014-1529",
    "CVE-2014-1530",
    "CVE-2014-1531",
    "CVE-2014-1532"
  );
  script_bugtraq_id(
    67123,
    67125,
    67129,
    67130,
    67131,
    67134,
    67135,
    67137
  );
  script_osvdb_id(
    106397,
    106401,
    106402,
    106403,
    106404,
    106406
  );

  script_name(english:"Mozilla Thunderbird < 24.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is a version prior to 24.5 and
is, therefore, potentially affected by the following vulnerabilities:

  - Memory issues exist that could lead to arbitrary code
    execution. (CVE-2014-1518, CVE-2014-1519)

  - An out-of-bounds read issue exists when decoding
    certain JPG images that could lead to a denial of
    service. (CVE-2014-1523)

  - A memory corruption issue exists due to improper
    validation of XBL objects that could lead to arbitrary
    code execution. (CVE-2014-1524)

  - A security bypass issue exists in the Web Notification
    API that could lead to arbitrary code execution.
    (CVE-2014-1529)

  - A cross-site scripting issue exists that could allow an
    attacker to load another website other than the URL for
    the website that is shown in the address bar.
    (CVE-2014-1530)

  - A use-after-free issue exists due to an 'imgLoader'
    object being freed when being resized.  This issue
    could lead to arbitrary code execution. (CVE-2014-1531)

  - A use-after-free issue exists during host resolution
    that could lead to arbitrary code execution.
    (CVE-2014-1532)");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-34.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-37.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-38.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-42.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-43.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-44.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-46.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 24.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'24.5', severity:SECURITY_HOLE, xss:TRUE);

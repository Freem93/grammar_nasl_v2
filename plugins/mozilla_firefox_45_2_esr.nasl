#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91546);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/08/09 17:45:02 $");

  script_cve_id(
    "CVE-2016-2818",
    "CVE-2016-2819",
    "CVE-2016-2821",
    "CVE-2016-2822",
    "CVE-2016-2824",
    "CVE-2016-2826",
    "CVE-2016-2828",
    "CVE-2016-2831"
  );
  script_bugtraq_id(
    91072,
    91074,
    91075
  );
  script_osvdb_id(
    139436,
    139437,
    139438,
    139439,
    139440,
    139441,
    139442,
    139443,
    139444,
    139445,
    139446,
    139447,
    139448,
    139455,
    139456,
    139457,
    139458,
    139460,
    139461,
    139463
  );
  script_xref(name:"MFSA", value:"2016-49");
  script_xref(name:"MFSA", value:"2016-50");
  script_xref(name:"MFSA", value:"2016-51");
  script_xref(name:"MFSA", value:"2016-52");
  script_xref(name:"MFSA", value:"2016-53");
  script_xref(name:"MFSA", value:"2016-55");
  script_xref(name:"MFSA", value:"2016-56");
  script_xref(name:"MFSA", value:"2016-58");

  script_name(english:"Firefox ESR 45.x < 45.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is
45.x prior to 45.2. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple memory corruption issues exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-2818)

  - An overflow condition exists that is triggered when
    handling HTML5 fragments in foreign contexts (e.g.,
    under <svg> nodes). An unauthenticated, remote attacker
    can exploit this to cause a heap-based buffer overflow,
    resulting in the execution of arbitrary code.
    (CVE-2016-2819)

  - A use-after-free error exists that is triggered when
    deleting DOM table elements in 'contenteditable' mode.
    An unauthenticated, remote attacker can exploit this to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2016-2821)

  - A spoofing vulnerability exists due to improper handling
    of SELECT elements. An unauthenticated, remote attacker
    can exploit this to spoof the contents of the address
    bar. (CVE-2016-2822)

  - An out-of-bounds write error exists in the ANGLE
    graphics library due to improper size checking while
    writing to an array during WebGL shader operations. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-2824)

  - A privilege escalation vulnerability exists in the
    Windows updater utility due to improper extraction of
    files from MAR archives. A local attacker can exploit
    this to replace the extracted files, allowing the
    attacker to gain elevated privileges. (CVE-2016-2826)

  - A use-after-free error exists that is triggered when
    destroying the recycle pool of a texture used during the
    processing of WebGL content. An unauthenticated, remote
    attacker can exploit this to dereference already freed
    memory, resulting in the execution of arbitrary code.
    (CVE-2016-2828)

  - A flaw exists that is triggered when handling paired
    fullscreen and pointerlock requests in combination with
    closing windows. An unauthenticated, remote attacker can
    exploit this to create an unauthorized pointerlock,
    resulting in a denial of service condition.
    Additionally, an attacker can exploit this to conduct
    spoofing and clickjacking attacks. (CVE-2016-2831)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-49/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-50/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-51/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-52/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-53/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-55/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-56/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-58/");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox ESR version 45.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/09");

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

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'45.2', min:'45.0', severity:SECURITY_HOLE);

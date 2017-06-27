#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55887);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/09/25 12:35:45 $");

  script_cve_id(
    "CVE-2011-0084",
    "CVE-2011-2985",
    "CVE-2011-2986",
    "CVE-2011-2987",
    "CVE-2011-2988",
    "CVE-2011-2989",
    "CVE-2011-2991",
    "CVE-2011-2992",
    "CVE-2011-2999"
  );
  script_bugtraq_id(
    49213,
    49224,
    49226,
    49227,
    49239,
    49242,
    49243,
    49245,
    49848
  );
  script_osvdb_id(
    74581,
    74588,
    74589,
    74590,
    74591,
    74592,
    74594,
    74595,
    75838
  );

  script_name(english:"Mozilla Thunderbird < 6.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that may be affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is earlier than 6.0 and thus, is
potentially affected by the following security issues :

  - Several memory safety bugs exist in the browser engine
    that may permit remote code execution. (CVE-2011-2985, 
    CVE-2011-2989, CVE-2011-2991, CVE-2011-2992)

  - A dangling pointer vulnerability exists in an SVG text
    manipulation routine. (CVE-2011-0084)

  - A buffer overflow vulnerability exists in WebGL when
    using an overly long shader program. (CVE-2011-2988)

  - A heap overflow vulnerability exists in WebGL's ANGLE
    library. (CVE-2011-2987)

  - A cross-origin data theft vulnerability exists when
    using canvas and Windows D2D hardware acceleration.
    (CVE-2011-2986)

  - There is an error in the implementation of the
    'window.location' JavaScript object when creating named
    frames. This can be exploited to bypass the same-origin
    policy and potentially conduct cross-site scripting
    attacks.(CVE-2011-2999)
");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-31.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-38.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 6.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'6.0', skippat:'^3\\.1\\.', severity:SECURITY_HOLE);
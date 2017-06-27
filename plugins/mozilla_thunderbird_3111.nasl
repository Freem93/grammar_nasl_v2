#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55289);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_cve_id(
    "CVE-2011-0083",
    "CVE-2011-0085",
    "CVE-2011-2362",
    "CVE-2011-2363",
    "CVE-2011-2364",
    "CVE-2011-2365",
    "CVE-2011-2371",
    "CVE-2011-2373",
    "CVE-2011-2374",
    "CVE-2011-2376",
    "CVE-2011-2377"
  );
  script_bugtraq_id(
    48357,
    48358,
    48360,
    48361,
    48365,
    48366,
    48367,
    48368,
    48369,
    48372,
    48373,
    48376
  );
  script_osvdb_id(
    73177,
    73179,
    73180,
    73181,
    73182,
    73183,
    73184,
    73185,
    73186,
    73187,
    73188
  );
  script_xref(name:"EDB-ID", value:"17974");
  script_xref(name:"EDB-ID", value:"17976");
  script_xref(name:"EDB-ID", value:"18531");
  script_xref(name:"Secunia", value:"44982");

  script_name(english:"Mozilla Thunderbird 3.1 < 3.1.11 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird 3.1 is earlier than 3.1.11. 
Such versions are potentially affected by the following security
issues :

  - Multiple memory safety issues can lead to application
    crashes and possibly remote code execution.
    (CVE-2011-2374, CVE-2011-2376, CVE-2011-2364,
    CVE-2011-2365)

  - A use-after-free issue when viewing XUL documents with
    scripts disabled could lead to code execution.
    (CVE-2011-2373)

  - A memory corruption issue due to multipart / 
    x-mixed-replace images could lead to memory corruption.
    (CVE-2011-2377)

  - When a JavaScript Array object has its length set to an
    extremely large value, the iteration of array elements
    that occurs when its reduceRight method is called could
    result in code execution due to an invalid index value
    being used. (CVE-2011-2371)

  - Multiple dangling pointer vulnerabilities could lead to
    code execution. (CVE-2011-0083, CVE-2011-2363,
    CVE-2011-0085)

  - An error in the way cookies are handled could lead to
    information disclosure. (CVE-2011-2362)");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-19.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-20.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-21.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-22.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-23.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-24.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-223/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-224/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-225/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 3.1.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox Array.reduceRight() Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'3.1.10', min:'3.1.11', severity:SECURITY_HOLE);
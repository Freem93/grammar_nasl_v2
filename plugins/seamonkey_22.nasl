#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55884);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id(
    "CVE-2011-2366",
    "CVE-2011-2367",
    "CVE-2011-2368",
    "CVE-2011-2369",
    "CVE-2011-2370",
    "CVE-2011-2371",
    "CVE-2011-2373",
    "CVE-2011-2375",
    "CVE-2011-2377",
    "CVE-2011-2598"
  );
  script_bugtraq_id(
    48319,
    48365,
    48369,
    48371,
    48372,
    48373,
    48375,
    48379,
    48380
  );
  script_osvdb_id(
    73101,
    73178,
    73182,
    73183,
    73184,
    73189,
    73190,
    73191,
    73192,
    73193
  );
  script_xref(name:"EDB-ID", value:"17974");
  script_xref(name:"EDB-ID", value:"17976");
  script_xref(name:"EDB-ID", value:"18531");

  script_name(english:"SeaMonkey < 2.2.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host contains a web browser that may be affected
by multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description",value:
"The installed version of SeaMonkey is earlier than 2.2.0.  As such,
it is potentially affected by the following security issues :

  - Errors in the WebGL implementation can allow the
    loading of WebGL textures from cross-domain images or
    allow the crash of the application and execution of 
    arbitrary code. (CVE-2011-2366, CVE-2011-2368)

  - An out-of-bounds read error exists in the WebGL 
    implementation that can lead to crashes and may allow
    an attacker to read arbitrary data from the GPU,
    including that of other processes. (CVE-2011-2367)

  - An error exists in the decoding of HTML-encoded
    entities contained in SVG elements. This error could lead
    to cross-site scripting attacks. (CVE-2011-2369)

  - An unspecified error exists that allows non-whitelisted
    sites to trigger an install dialog for add-ons and
    themes. (CVE-2011-2370)

  - When a JavaScript Array object has its length set to an
    extremely large value, the iteration of array elements
    that occurs when its reduceRight method is called could
    result in code execution due to an invalid index value
    being used. (CVE-2011-2371)

  - A use-after-free error when viewing XUL documents with
    scripts disabled could lead to code execution.
    (CVE-2011-2373)

  - Multiple memory safety issues can lead to application
    crashes and possibly remote code execution.
    (CVE-2011-2375)

  - A memory corruption issue due to multipart / 
    x-mixed-replace images could lead to memory corruption.
    (CVE-2011-2377)");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-19.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-20.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-21.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-22.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-25.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-26.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-27.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-28.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/known-vulnerabilities/seamonkey20.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 2.2.0 or later.");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.2', severity:SECURITY_HOLE);
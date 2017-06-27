#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57353);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id(
    "CVE-2011-3658",
    "CVE-2011-3660",
    "CVE-2011-3661",
    "CVE-2011-3663",
    "CVE-2011-3665",
    "CVE-2011-3671"
  );
  script_bugtraq_id(
    51133,
    51134,
    51135,
    51136,
    51138,
    54080
  );
  script_osvdb_id(77951, 77952, 77953, 77954, 77956, 83115);
  script_xref(name:"EDB-ID", value:"18847");

  script_name(english:"SeaMonkey < 2.6.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host contains a web browser that is affected by
several vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The installed version of SeaMonkey is earlier than 2.6.0.  Such
versions are potentially affected by the following security issues :

  - An out-of-bounds memory access error exists in the
    'SVG' implementation and can be triggered when 'SVG'
    elements are removed during a 'DOMAttrModified' event
    handler. (CVE-2011-3658)

  - Various memory safety errors exist that can lead to
    memory corruption and possible code execution.
    (CVE-2011-3660)

  - An error exists in the 'YARR' regular expression
    library that can cause application crashes when
    handling certain JavaScript statements. (CVE-2011-3661)

  - It is possible to detect keystrokes using 'SVG'
    animation 'accesskey' events even when JavaScript is
    disabled. (CVE-2011-3663)

  - It is possible to crash the application when 'OGG'
    'video' elements are scaled to extreme sizes.
    (CVE-2011-3665)

  - A use-after-free error exists related to the function
    'nsHTMLSelectElement' that can allow arbitrary code
    execution during operations such as removal of a
    parent node of an element. (CVE-2011-3671)"
  );

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-056/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-128/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/523754/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-53.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-54.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-55.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-56.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-58.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-41.html");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=739343");

  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 2.6.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox nsSVGValue Out-of-Bounds Access Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/20");

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

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.6.0', severity:SECURITY_HOLE);
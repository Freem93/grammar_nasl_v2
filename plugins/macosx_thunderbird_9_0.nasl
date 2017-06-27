#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57361);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id(
    "CVE-2011-3658",
    "CVE-2011-3660",
    "CVE-2011-3661",
    "CVE-2011-3663",
    "CVE-2011-3664",
    "CVE-2011-3665",
    "CVE-2011-3671"
  );
  script_bugtraq_id(51133, 51134, 51135, 51136, 51137, 51138, 54080);
  script_osvdb_id(77951, 77952, 77953, 77954, 77955, 77956, 83115);

  script_name(english:"Thunderbird 8.x Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an email client that is potentially
affected by several vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird 8.x is potentially affected by
the following security issues :

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

  - An error exists related to plugins that can allow a NULL
    pointer to be dereferenced when a plugin deletes its
    containing DOM frame during a call from that frame. It
    may be possible for a non-NULL pointer to be
    dereferenced thereby opening up the potential for
    further exploitation. (CVE-2011-3664)

  - It is possible to crash the application when 'OGG'
    'video' elements are scaled to extreme sizes.
    (CVE-2011-3665)

  - A use-after-free error exists related to the function
    'nsHTMLSelectElement' that can allow arbitrary code
    execution during operations such as removal of a
    parent node of an element. (CVE-2011-3671)");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-128/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/523754/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-41.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-53.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-54.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-55.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-56.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-57.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-58.html");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=739343");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 9.0 or later.");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 8)
{
  if (report_verbosity > 0)
  {
    info +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 9.0' + '\n';
    security_hole(port:0, extra:info);
  }
  else security_hole(0);
  exit(0);
}
else exit(0, "Thunderbird 8.x is not installed.");

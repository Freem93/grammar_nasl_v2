#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55288);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_cve_id(
    "CVE-2011-2366",
    "CVE-2011-2367",
    "CVE-2011-2368",
    "CVE-2011-2369",
    "CVE-2011-2370",
    "CVE-2011-2371",
    "CVE-2011-2373",
    "CVE-2011-2374",
    "CVE-2011-2375",
    "CVE-2011-2377",
    "CVE-2011-2598"
  );
  script_bugtraq_id(
    48319, 
    48361,
    48365,
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
    73177,
    73178,
    73180,
    73181,
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
  script_xref(name:"Secunia", value:"44982");

  script_name(english:"Firefox 4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox 4 is potentially affected by the
following security issues :

  - Multiple memory safety issues can lead to application 
    crashes and possibly remote code execution.
    (CVE-2011-2374, CVE-2011-2375)

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

  - It is possible for an image from a different domain to
    be loaded into a WebGL texture which could be used to 
    steal image data from a different site. (CVE-2011-2366,
    CVE-2011-2598)

  - An out-of-bounds read issue and an invalid write issue
    could cause the application to crash. (CVE-2011-2367,
    CVE-2011-2368)

  - HTML-encoded entities are improperly decoded when
    displayed inside SVG elements which could lead to 
    cross-site scripting attacks. (CVE-2011-2369)

  - It is possible for a non-whitelisted site to trigger an
    install dialog for add-ons and themes. (CVE-2011-2370)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9382419d");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-19.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-20.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-21.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-22.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-25.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-26.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-27.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-28.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 5.0 or later.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'5.0', skippat:'^3\\.6\\.', severity:SECURITY_HOLE);
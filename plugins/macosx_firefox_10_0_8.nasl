#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62575);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id(
    "CVE-2012-3982",
    "CVE-2012-3983",
    "CVE-2012-3986",
    "CVE-2012-3988",
    "CVE-2012-3990",
    "CVE-2012-3991",
    "CVE-2012-3992",
    "CVE-2012-3993",
    "CVE-2012-3994",
    "CVE-2012-3995",
    "CVE-2012-4179",
    "CVE-2012-4180",
    "CVE-2012-4181",
    "CVE-2012-4182",
    "CVE-2012-4183",
    "CVE-2012-4184",
    "CVE-2012-4185",
    "CVE-2012-4186",
    "CVE-2012-4187",
    "CVE-2012-4188"
  );
  script_bugtraq_id(
    55922, 
    55924, 
    55930, 
    55931,
    56118,
    56119,
    56120,
    56121,
    56123,
    56125,
    56126,
    56127,
    56128,
    56129,
    56130,
    56131,
    56135,
    56136,
    56140,
    56145
  );
  script_osvdb_id(
    86094,
    86095,
    86096,
    86098,
    86099,
    86100,
    86101,
    86102,
    86103,
    86104,
    86108,
    86109,
    86110,
    86111,
    86112,
    86113,
    86114,
    86115,
    86116,
    86117
  );


  script_name(english:"Firefox < 10.0.8 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Firefox is earlier than 10.0.8 and thus, is
affected by the following vulnerabilities :

  - Several memory safety bugs exist in the browser engine 
    used in Mozilla-based products that could be exploited 
    to execute arbitrary code. (CVE-2012-3983)

  - Some methods of a feature used for testing 
    (DOMWindowUtils) are not properly protected and may be 
    called through script by web pages. (CVE-2012-3986)

  - A potentially exploitable denial of service may be 
    caused by a combination of invoking full-screen mode and 
    navigating backwards in history. (CVE-2012-3988)

  - When the 'GetProperty' function is invoked through JSAP, 
    security checking can be bypassed when getting cross-
    origin properties, potentially allowing arbitrary code 
    execution. (CVE-2012-3991)

  - The 'location' property can be accessed by binary 
    plugins through 'top.location' and 'top' can be shadowed 
    by 'Object.defineProperty', potentially allowing cross-
    site scripting attacks through plugins. (CVE-2012-3994)

  - The Chrome Object Wrapper (COW) has flaws that could 
    allow access to privileged functions, allowing for cross-
    site scripting attacks or arbitrary code execution. 
    (CVE-2012-3993, CVE-2012-4184)

  - The 'location.hash' property is vulnerable to an attack 
    that could allow an attacker to inject script or 
    intercept post data. (CVE-2012-3992)

  - The 'Address Sanitizer' tool is affected by multiple, 
    potentially exploitable use-after-free flaws. 
    (CVE-2012-3990, CVE-2012-3995, CVE-2012-4179, 
    CVE-2012-4180, CVE-2012-4181, CVE-2012-4182, 
    CVE-2012-4183)

  - The 'Address Sanitizer' tool is affected by multiple, 
    potentially exploitable heap memory corruption issues. 
    (CVE-2012-4185, CVE-2012-4186, CVE-2012-4187, 
    CVE-2012-4188)"
  );
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-87/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-86/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-85/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-84/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-83/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-82/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-81/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-79/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-77/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-74/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 10.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 5.0 - 15.0.1 __exposedProps__ XCS Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");
kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'10.0.8', severity:SECURITY_HOLE, xss:TRUE);
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62996);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/17 17:02:53 $");

  script_cve_id(
    "CVE-2012-4201",
    "CVE-2012-4202",
    "CVE-2012-4204",
    "CVE-2012-4205",
    "CVE-2012-4207",
    "CVE-2012-4208",
    "CVE-2012-4209",
    "CVE-2012-4212",
    "CVE-2012-4213",
    "CVE-2012-4214",
    "CVE-2012-4215",
    "CVE-2012-4216",
    "CVE-2012-4217",
    "CVE-2012-4218",
    "CVE-2012-5829",
    "CVE-2012-5830",
    "CVE-2012-5833",
    "CVE-2012-5835",
    "CVE-2012-5836",
    "CVE-2012-5838",
    "CVE-2012-5839",
    "CVE-2012-5840",
    "CVE-2012-5841",
    "CVE-2012-5842",
    "CVE-2012-5843"
  );
  script_bugtraq_id(
    56611,
    56612,
    56613,
    56614,
    56616,
    56618,
    56621,
    56627,
    56628,
    56629,
    56630,
    56631,
    56632,
    56633,
    56634,
    56635,
    56636,
    56637,
    56638,
    56639,
    56640,
    56641,
    56642,
    56643,
    56644
  );
  script_osvdb_id(
    87581,
    87582,
    87583,
    87585,
    87587,
    87588,
    87589,
    87591,
    87592,
    87593,
    87594,
    87595,
    87596,
    87597,
    87598,
    87599,
    87601,
    87602,
    87603,
    87604,
    87605,
    87606,
    87607,
    87608,
    87609,
    89007
  );

  script_name(english:"Thunderbird 16.x Multiple Vulnerabilities (Mac OS X)");
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
"The installed version of Thunderbird 16.x is potentially affected by
the following security issues :
  
  - Several memory safety bugs exist in the browser engine 
    used in Mozilla-based products that could be exploited 
    to execute arbitrary code. (CVE-2012-5842,
    CVE-2012-5843)

  - An error exists in the method
    'image::RasterImage::DrawFrameTo' related to GIF images
    that could allow a heap-based buffer overflow, leading to
    arbitrary code execution. (CVE-2012-4202)

  - An error exists related to SVG text and CSS properties
    that could lead to application crashes. (CVE-2012-5836)

  - The JavaScript function 'str_unescape' could allow
    arbitrary code execution. (CVE-2012-4204)

  - 'XMLHttpRequest' objects inherit incorrect principals
    when created in sandboxes that could allow cross-site
    request forgery attacks (CSRF). (CVE-2012-4205)

  - 'XrayWrappers' can expose DOM properties that are
    not meant to be accessible outside of the chrome
    compartment. (CVE-2012-4208)

  - Errors exist related to 'evalInSandbox', 'HZ-GB-2312'
    charset, frames and the 'location' object, and
    'cross-origin wrappers' that could allow cross-site
    scripting (XSS) attacks. (CVE-2012-4201, CVE-2012-4207,
    CVE-2012-4209 CVE-2012-5841)

  - Various use-after-free, out-of-bounds read and buffer
    overflow errors exist that could potentially lead to
    arbitrary code execution. (CVE-2012-4212, CVE-2012-4213,
    CVE-2012-4214, CVE-2012-4215, CVE-2012-4216,
    CVE-2012-4217, CVE-2012-4218, CVE-2012-5829,
    CVE-2012-5830, CVE-2012-5833, CVE-2012-5835,
    CVE-2012-5838, CVE-2012-5839, CVE-2012-5840)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-91.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-92.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-93.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-94.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-96.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-97.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-99.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-100.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-101.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-103.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-105.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-106.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 17.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include("mozilla_version.inc");
kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

mozilla_check_version(product:'thunderbird', version:version, path:path, esr:FALSE, fix:'17.0', skippat:'^10\\.0\\.', severity:SECURITY_HOLE, xss:TRUE, xsrf:TRUE);

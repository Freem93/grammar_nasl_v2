#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46850);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id(
    "CVE-2010-1772",
    "CVE-2010-1773",
    "CVE-2010-2295",
    "CVE-2010-2296",
    "CVE-2010-2297",
    "CVE-2010-2298",
    "CVE-2010-2299",
    "CVE-2010-2300",
    "CVE-2010-2301",
    "CVE-2010-2302"
  );
  script_bugtraq_id(40651, 41573, 41575);
  script_osvdb_id(
    65307,
    65311,
    65322,
    65326,
    65329,
    65330,
    65399,
    65400,
    65403,
    65406
  );

  script_name(english:"Google Chrome < 5.0.375.70 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 5.0.375.70.  As such, it is reportedly affected by multiple
vulnerabilities :

  - A cross-origin keystroke redirection vulnerability.
    (Issue #15766)

  - A cross-origin bypass in DOM methods. (Issue #39985)

  - A memory error exists in table layout. (Issue #42723)

  - It is possible to escape the sandbox in Linux.
    (Issue #43304)

  - A stale pointer exists in bitmap. (Issue #43307)

  - A memory corruption vulnerability exists in DOM node
    normalization. (Issue #43315)

  - A memory corruption vulnerability exists in text
    transforms. (Issue #43487)

  - A cross-site scripting vulnerability exists in the
    innerHTML property of textarea. (Issue #43902)

  - A memory corruption vulnerability exists in font
    handling. (Issue #44740)

  - Geolocation events fire after document deletion.
    (Issue #44868)

  - A memory corruption vulnerability exists in the
    rendering of list markers. (Issue #44955)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c406bbd");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 5.0.375.70 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}


include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'5.0.375.70', xss:TRUE, severity:SECURITY_HOLE);

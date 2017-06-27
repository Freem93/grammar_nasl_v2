#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58536);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id(
    "CVE-2011-3057",
    "CVE-2011-3058",
    "CVE-2011-3059",
    "CVE-2011-3060",
    "CVE-2011-3061",
    "CVE-2011-3062",
    "CVE-2011-3063",
    "CVE-2011-3064",
    "CVE-2011-3065",
    "CVE-2012-0772",
    "CVE-2012-0773"
  );
  script_bugtraq_id(52762, 53222);
  script_osvdb_id(
    80604,
    80706,
    80707,
    80736,
    80737,
    80738,
    80739,
    80740,
    80741,
    80742,
    80743
  );

  script_name(english:"Google Chrome < 18.0.1025.142 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 18.0.1025.142 and is, therefore, affected by the following
vulnerabilities :

  - An error exists in the v8 JavaScript engine that can
    allow invalid reads. (CVE-2011-3057)

  - An unspecified error exists related to bad interaction
    and 'EUC-JP'. This can lead to cross-site scripting
    attacks. (CVE-2011-3058)

  - Out-of-bounds read errors exist related to SVG text
    handling and text fragment handling. (CVE-2011-3059,
    CVE-2011-3060)

  - A certificate checking error exists related to the
    SPDY protocol. (CVE-2011-3061)

  - An off-by-one error exists in the 'OpenType Sanitizer'.
    (CVE-2011-3062)

  - Navigation requests from the renderer are not validated
    carefully enough.(CVE-2011-3063)

  - A use-after-free error exists related to SVG clipping.
    (CVE-2011-3064)

  - An unspecified memory corruption error exists related
    to 'Skia'. (CVE-2011-3065)

  - The bundled version of Adobe Flash Player contains
    errors related to ActiveX and the NetStream class.
    These errors can allow memory corruption, denial of
    service via application crashes and possibly code
    execution. (CVE-2012-0772, CVE-2012-0773)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfbac052");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db237f54");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 18.0.1025.142 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'18.0.1025.142', xss:TRUE, severity:SECURITY_HOLE);

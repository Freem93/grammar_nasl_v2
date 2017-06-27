#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(52589);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2014/10/03 10:46:58 $");

  script_cve_id(
    "CVE-2011-1185",
    "CVE-2011-1187",
    "CVE-2011-1188",
    "CVE-2011-1189",
    "CVE-2011-1190",
    "CVE-2011-1191",
    "CVE-2011-1193",
    "CVE-2011-1194",
    "CVE-2011-1195",
    "CVE-2011-1196",
    "CVE-2011-1197",
    "CVE-2011-1198",
    "CVE-2011-1199",
    "CVE-2011-1200",
    "CVE-2011-1201",
    "CVE-2011-1202",
    "CVE-2011-1203",
    "CVE-2011-1204",
    "CVE-2011-1285",
    "CVE-2011-1286"
  );
  script_bugtraq_id(46785, 47668, 50062);
  script_osvdb_id(
    72094,
    72472,
    72475,
    72476,
    72477,
    72478,
    72479,
    72481,
    72482,
    72483,
    72484,
    72485,
    72486,
    72487,
    72488,
    72489,
    72490,
    72491,
    72492,
    72493,
    72494,
    81526
  );
  script_xref(name:"Secunia", value:"43683");

  script_name(english:"Google Chrome < 10.0.648.127 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 10.0.648.127.  Such versions are reportedly affected by multiple
vulnerabilities :

  - It may be possible to navigate or close the top location
    in a sandboxed frame. (Issue #42574, #42765)

  - A cross-origin error message leak exists. (Issue #69187)

  - A memory corruption issue exists with counter nodes.
    (Issue #69628)

  - An unspecified issue exists with stale nodes in box
    layout. (Issue #70027)

  - A cross-origin error message leak exists with workers.
    (Issue #70336)

  - A use-after-free error exists with DOM URL handling.
    (Issue #70442)

  - A same origin policy bypass exists in v8. (Issue #70877)

  - It may be possible to bypass the pop-up blocker.
    (Issue #70885, #71167)

  - A use-after-free error exists in document script
    lifetime handling. (Issue #71763)

  - An out-of-bounds write issue exists in the OGG
    container. (Issue #71788)

  - A stale pointer exists in table painting. (Issue #72028)

  - A corrupt out-of-bounds structure may be used in video
    code. (Issue #73026)

  - It may be possible to crash the application with the
    DataView object. (Issue #73066)

  - A bad cast exists in text rendering. (Issue #73134)

  - A stale pointer exists in the WebKit context code.
    (Issue #73196)

  - It may be possible for heap addresses to leak in XSLT.
    (Issue #73716)

  - A stale pointer exists with SVG cursors. (Issue #73746)

  - It is possible for the DOM tree to be corrupted with
    attribute handling. (Issue #74030)

  - An unspecified corruption exists via re-entrancy of
    RegExp code. (Issue #74662)

  - An invalid memory access exists in v8. (Issue #74675)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?903021a5");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 10.0.648.127 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'10.0.648.127', severity:SECURITY_WARNING);

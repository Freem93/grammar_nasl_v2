#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52501);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id(
    "CVE-2011-1107",
    "CVE-2011-1108",
    "CVE-2011-1109",
    "CVE-2011-1110",
    "CVE-2011-1111",
    "CVE-2011-1112",
    "CVE-2011-1114",
    "CVE-2011-1115",
    "CVE-2011-1116",
    "CVE-2011-1117",
    "CVE-2011-1118",
    "CVE-2011-1119",
    "CVE-2011-1120",
    "CVE-2011-1121",
    "CVE-2011-1122",
    "CVE-2011-1123",
    "CVE-2011-1124",
    "CVE-2011-1125"
  );
  script_bugtraq_id(46614, 47020);
  script_osvdb_id(
    72268,
    72269,
    72270,
    72271,
    72272,
    72273,
    72274,
    72275,
    72276,
    72277,
    72278,
    72279,
    72281,
    72282,
    72283,
    72284,
    72285,
    72286
  );
  script_xref(name:"Secunia", value:"43519");

  script_name(english:"Google Chrome < 9.0.597.107 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 9.0.597.107.  Such versions are reportedly affected by multiple
vulnerabilities :

  - An unspecified error exists in the URL bar operations
    which can allow spoofing attacks. (Issue #54262)

  - An unspecified error exists in the processing of
    JavaScript dialogs. (Issue #63732)

  - An unspecified error exists in the processing of CSS
    nodes which can leave stale pointers in memory.
    (Issue #68263)

  - An unspecified error exists in the processing of key
    frame rules which can leave stale pointers in memory.
    (Issue #68741)

  - An unspecified error exists in the processing of form
    controls which can lead to application crashes.
    (Issue #70078)

  - An unspecified error exists in the rendering of SVG
    animations and other SVG content which can leave stale
    pointers in memory. (Issue #70244, #71296)

  - An unspecified error exists in the processing of tables
    which can leave stale nodes behind. (Issue #71114)

  - An unspecified error exists in the processing of tables
    which can leave stale pointers in memory. (Issue #71115)

  - An unspecified error exists in the processing of XHTML
    which can leave stale nodes behind. (Issue #71386)

  - An unspecified error exists in the processing of
    textarea elements which can lead to application
    crashes. (Issue #71388)

  - An unspecified error exists in the processing of device
    orientation which can leave stale pointers in memory.
    (Issue #71595)

  - An unspecified error exists in WebGL which allows
    out-of-bounds memory accesses. (Issue #71717, #71960)

  - An integer overflow exists in the processing of
    textarea elements which can lead to application
    crashes. (Issue #71855)

  - An unspecified error exists which exposes internal
    extension functions. (Issue #72214)

  - A use-after-free error exists in the processing of
    blocked plugins. (Issue #72437)

  - An unspecified error exists in the processing of
    layouts which can leave stale pointers in memory.
    (Issue #73235)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ac088da");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 9.0.597.107 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'9.0.597.107', severity:SECURITY_HOLE);

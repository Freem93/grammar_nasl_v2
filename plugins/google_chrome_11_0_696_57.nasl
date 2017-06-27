#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53569);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/04/03 14:49:09 $");

  script_cve_id(
    "CVE-2011-1303",
    "CVE-2011-1304",
    "CVE-2011-1434",
    "CVE-2011-1435",
    "CVE-2011-1437",
    "CVE-2011-1438",
    "CVE-2011-1440",
    "CVE-2011-1441",
    "CVE-2011-1442",
    "CVE-2011-1443",
    "CVE-2011-1445",
    "CVE-2011-1446",
    "CVE-2011-1447",
    "CVE-2011-1448",
    "CVE-2011-1449",
    "CVE-2011-1450",
    "CVE-2011-1451",
    "CVE-2011-1452",
    "CVE-2011-1454",
    "CVE-2011-1455",
    "CVE-2011-1456"
  );
  script_bugtraq_id(47604);
  script_osvdb_id(
    72196,
    72197,
    72199,
    72200,
    72202,
    72203,
    72205,
    72206,
    72207,
    72208,
    72210,
    72211,
    72212,
    72213,
    72214,
    72215,
    72216,
    72217,
    72218,
    72219,
    72220,
    90384,
    90385
  );

  script_name(english:"Google Chrome < 11.0.696.57 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 11.0.696.57.  Such versions of Chrome are affected by multiple
vulnerabilities:

  - A stale pointer exists in floating object handling.
    (Issue #61502)

  - It may be possible to bypass the pop-up blocker via
    plug-ins. (Issue #70538)

  - There is a lack of thread safety in MIME handling.
    (Issue #71586)

  - A bad extension with 'tabs' permission can capture local
    files. (Issue #72523)

  - Multiple integer overflows exist in float rendering.
    (Issue #73526)

  - A same origin policy violation exists with blobs.
    (Issue #74653)

  - A use-after-free error exists with <ruby> tags and CSS.
    (Issue #75186)

  - A bad cast exists with floating select lists.
    (Issue #75347)

  - Corrupt node trees exist with mutation events.
    (Issue #75801)

  - Multiple stale pointers exist in layering code.
    (Issue #76001)

  - An out-of-bounds read exists in SVG. (Issue #76646)

  - It is possible to spoof the URL bar with navigation
    errors and interrupted loads. (Issue #76666, #77507,
    #78031)

  - A stale pointer exists in drop-down list handling.
    (Issue #76966)

  - A stale pointer exists in height calculations.
    (Issue #77130)

  - A use-after-free error exists in WebSockets.
    (Issue #77346)

  - Multiple dandling pointers exist in file dialogs.
    (Issue #77349)

  - Multiple dangling pointers exist in DOM id map.
    (Issue #77463)

  - It is possible to spoof the URL bar with redirect and
    manual reload. (Issue #77786)

  - A use-after-free issue exists in DOM id handling.
    (Issue #79199)

  - An out-of-bounds read exists when handling
    multipart-encoded PDFs. (Issue #79361)

  - Multiple stale pointers exist with PDF forms.
    (Issue #79364)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5cd0fc79");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 11.0.696.57 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'11.0.696.57', severity:SECURITY_HOLE);

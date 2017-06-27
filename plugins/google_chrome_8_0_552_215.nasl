#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(50977);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id(
    "CVE-2010-4482",
    "CVE-2010-4483",
    "CVE-2010-4484",
    "CVE-2010-4485",
    "CVE-2010-4486",
    "CVE-2010-4487",
    "CVE-2010-4488",
    "CVE-2010-4489",
    "CVE-2010-4490",
    "CVE-2010-4491",
    "CVE-2010-4492",
    "CVE-2010-4493",
    "CVE-2010-4494"
  );
  script_bugtraq_id(45170, 45617);
  script_osvdb_id(
    69661,
    69662,
    69663,
    69664,
    69665,
    69666,
    69667,
    69668,
    69669,
    69670,
    69671,
    69672,
    69673
  );
  script_xref(name:"MSVR", value:"MSVR11-002");
  script_xref(name:"Secunia", value:"42109");

  script_name(english:"Google Chrome < 8.0.552.215 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 8.0.552.215.  Such versions are reportedly affected by multiple
vulnerabilities :

  - It may be possible to bypass the pop-up blocker.
    (Issue #17655)

  - A cross-origin video theft vulnerability exists related
    to canvas. (Issue #55745)

  - An unspecified crash exists when handling HTML5
    databases. (Issue #56237)

  - Excessive file dialogs could lead to a browser crash.
    (Issue #58329)

  - A use after free error exists in history handling.
    (Issue #59554)

  - It may be possible to crash the browser when performing
    http proxy  authentication. (Issue #61701)

  - An out-of-bounds read regression exists in the WebM
    video support. (Issue #61701)

  - It may be possible to crash the browser due to bad
    indexing with malformed video. (Issue #62127)

  - A memory corruption issue exists relating to malicious
    privileged extension. (Issue #62168)

  - A use-after-free error exists in the handling of SVG
    animations. (Issue #62401)

  - A use-after-free error exists in the mouse dragging
    event handling. (Issue #63051)

  - A double free error exists in XPath handling.
    (Issue #63444)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?986a631f");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 8.0.552.215 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/03");

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
google_chrome_check_version(installs:installs, fix:'8.0.552.215', severity:SECURITY_HOLE);

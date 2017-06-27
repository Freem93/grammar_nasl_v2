#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54989);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id(
    "CVE-2011-1808",
    "CVE-2011-1809",
    "CVE-2011-1810",
    "CVE-2011-1811",
    "CVE-2011-1812",
    "CVE-2011-1813",
    "CVE-2011-1814",
    "CVE-2011-1815",
    "CVE-2011-1816",
    "CVE-2011-1817",
    "CVE-2011-1818",
    "CVE-2011-1819",
    "CVE-2011-2332",
    "CVE-2011-2342"
  );
  script_bugtraq_id(48129);
  script_osvdb_id(
    72778,
    72779,
    72780,
    72781,
    72782,
    72783,
    72784,
    72785,
    72786,
    72787,
    72788,
    72789,
    72790,
    76353
  );

  script_name(english:"Google Chrome < 12.0.742.91 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 12.0.742.91.  Such versions of Chrome are affected by multiple
vulnerabilities:

  - Use-after-free errors exist in the handling of float
    variables, accessibility functionality, developer
    tools and an image loader. (Issues #73962, #79746,
    #75496, #80358, #81949)

  - An information disclosure vulnerability exists that
    can leak browser history via CSS. (Issue #75643)

  - An unspecified error exists related to handling
    many form submissions. (Issue #76034)

  - An unspecified extensions permissions bypass
    vulnerability exists. (Issue #77026)

  - An unspecified error in the extensions framework can
    leave stale pointers behind. (Issue #78516).

  - An unspecified error can lead to a read of an
    uninitialized pointer. (Issue #79362)

  - An extension can inject script into a new tab page or
    into the browser chrome. (Issues #79862, #83010)

  - An unspecified error exists which can corrupt memory
    when the browser history is deleted. (Issue #81916)

  - Errors exist that allow the same origin policy to be
    bypassed in 'v8' and 'DOM'. (Issues #83275, #83743)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27ba5b5d");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 12.0.742.91 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/07");

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
google_chrome_check_version(installs:installs, fix:'12.0.742.91', severity:SECURITY_HOLE);

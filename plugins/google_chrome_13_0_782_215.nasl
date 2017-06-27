#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55959);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id(
    "CVE-2011-2806",
    "CVE-2011-2821",
    "CVE-2011-2822",
    "CVE-2011-2823",
    "CVE-2011-2824",
    "CVE-2011-2825",
    "CVE-2011-2826",
    "CVE-2011-2827",
    "CVE-2011-2828",
    "CVE-2011-2829"
#    "CVE-2011-2839" < Linux only
  );
  script_bugtraq_id(49279);
  script_osvdb_id(
    74691,
    74692,
    74693,
    74694,
    74695,
    74696,
    74697,
    74698,
    74699,
    74700
  );

  script_name(english:"Google Chrome < 13.0.782.215 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 13.0.782.215 and is potentially affected by several
vulnerabilities:

  - An unspecified error related to command line URL
    parsing exists. (Issue #72492)

  - Use-after-free errors related to line box handling,
    counter nodes, custom fonts, and text searching.
    (Issue #82552, #88216, #88670, #90668)

  - A double-free error related to libxml XPath handling
    exists. (Issue #89402)

  - An error related to empty origins exists that can allow
    cross-domain violation. (Issue #87453)

  - A memory corruption error exists related to vertex
    handling. (Issue #89836)

  - An out-of-bounds write error exists in the v8
    JavaScript engine. (Issue #91517)

  - An integer overrun error exists in the handling of
    uniform arrays. (Issue #91598)");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-054/");
  # http://googlechromereleases.blogspot.com/2011/08/stable-channel-update_22.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ab50493");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 13.0.782.215 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/23");

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
google_chrome_check_version(installs:installs, fix:'13.0.782.215', severity:SECURITY_HOLE);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55765);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id(
    "CVE-2011-2358",
    "CVE-2011-2359",
    "CVE-2011-2360",
    "CVE-2011-2361",
#   "CVE-2011-2782", < Linux only
    "CVE-2011-2783",
    "CVE-2011-2784",
    "CVE-2011-2785",
    "CVE-2011-2786",
    "CVE-2011-2787",
    "CVE-2011-2788",
    "CVE-2011-2789",
    "CVE-2011-2790",
    "CVE-2011-2791",
    "CVE-2011-2792",
    "CVE-2011-2793",
    "CVE-2011-2794",
    "CVE-2011-2795",
    "CVE-2011-2796",
    "CVE-2011-2797",
    "CVE-2011-2798",
    "CVE-2011-2799",
    "CVE-2011-2800",
    "CVE-2011-2801",
    "CVE-2011-2802",
    "CVE-2011-2803",
    "CVE-2011-2804",
    "CVE-2011-2805",
    "CVE-2011-2818",
    "CVE-2011-2819"
  );
  script_bugtraq_id(48960);
  script_osvdb_id(
    74228,
    74229,
    74230,
    74231,
#   74232,  < Linux only
    74233,
    74234,
    74235,
    74236,
    74237,
    74238,
    74239,
    74240,
    74241,
    74242,
    74243,
    74244,
    74245,
    74246,
    74247,
    74248,
    74250,
    74251,
    74252,
    74253,
    74254,
    74255,
    74256,
    74257,
    74258
  );

  script_name(english:"Google Chrome < 13.0.782.107 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 13.0.782.107.  As such, it is potentially affected by several
vulnerabilities :

  - An unspecified error exists related to extension
    installation and confirmation dialogs. (Issue #75821)

  - A stale pointer issue exists related to bad line box
    tracking and rendering. (Issue #78841)

  - A security bypass issue exists related to file download
    prompts. (Issue #79266)

  - A string handling issue exists related to the HTTP
    basic authentication dialog box. (Issue #79426)

  - Developer mode NPAPI extensions do not always prompt
    a user before installation. (Issue #83273)

  - A local, unspecified path disclosure issue exists and
    is related to the GL log. (Issue #83841)

  - Extensions' homepage URLs are not properly sanitized.
    (Issue #84402)

  - The browser's speech-input element is not always on the
    screen at required times. (Issue #84600)

  - A re-entrancy issue related to the GPU lock can cause
    the browser to crash. (Issue #84805)

  - A buffer overflow exists in the inspector
    serialization. (Issue #85559)

  - Use-after-free errors exist related to the Pepper
    plugin, floating styles, float removal, media
    selectors, Skia, resource caching, HTML range handling,
    frame loading and display box rendering that can cause
    the browser to crash. (Issues #85808, #86502, #87148,
    #87227,# 87548, #87729, #87925, #88846, #88889)

  - An out-of-bounds write error exists related to the
    Internal Components for Unicode (ICU). (Issue #86900)

  - Out-of-bounds read errors exist related to text
    iteration and Skia paths. (Issue #87298)

  - A cross-frame function leak exists. (Issue #87339)

  - Access to internal schemes is not properly enforced.
    (Issue #87815)

  - Client side redirect targets may be leaked to remote
    locations. (Issue #88337)

  - Const lookups can cause the V8 JavaScript engine to
    crash. (Issue #88591)

  - Certain PDF files with nested functions can cause the
    browser to crash. (Issue #89142)

  - The same origin policy is not properly enforced which
    can lead to cross-origin script injection and other
    cross-origin violations. (Issues #89520, #90222)");

  # http://googlechromereleases.blogspot.com/2011/08/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?739f0064");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 13.0.782.107 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/04");

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
google_chrome_check_version(installs:installs, fix:'13.0.782.107', severity:SECURITY_HOLE);

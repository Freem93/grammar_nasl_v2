#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56230);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/09 13:37:53 $");

  script_cve_id(
    "CVE-2011-2830",
    "CVE-2011-2834",
    "CVE-2011-2835",
    "CVE-2011-2836",
    "CVE-2011-2838",
    "CVE-2011-2839",
    "CVE-2011-2840",
    "CVE-2011-2841",
    "CVE-2011-2843",
    "CVE-2011-2844",
    "CVE-2011-2846",
    "CVE-2011-2847",
    "CVE-2011-2848",
    "CVE-2011-2849",
    "CVE-2011-2850",
    "CVE-2011-2851",
    "CVE-2011-2852",
    "CVE-2011-2853",
    "CVE-2011-2854",
    "CVE-2011-2855",
    "CVE-2011-2856",
    "CVE-2011-2857",
    "CVE-2011-2858",
    "CVE-2011-2859",
    "CVE-2011-2860",
    "CVE-2011-2861",
    "CVE-2011-2862",
    "CVE-2011-2864",
    "CVE-2011-2874",
    "CVE-2011-2875",
    "CVE-2011-3234"
  );
  script_bugtraq_id(49658, 49933);
  script_osvdb_id(
    75536,
    75537,
    75539,
    75540,
    75541,
    75543,
    75544,
    75545,
    75546,
    75547,
    75548,
    75549,
    75550,
    75551,
    75552,
    75553,
    75554,
    75555,
    75556,
    75557,
    75558,
    75559,
    75560,
    75561,
    75562,
    75563,
    75564,
    75565,
    75566,
    75567
  );
  script_xref(name:"EDB-ID", value:"17929");

  script_name(english:"Google Chrome < 14.0.835.163 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 14.0.835.163 and is affected by multiple vulnerabilities:

  - A race condition exists related to the certificate
    cache. (Issue #49377)

  - The Windows Media Player plugin allows click-free
    access to the system Flash. (Issue #51464)

  - MIME types are not treated authoritatively at plugin
    load time. (Issue #75070)

  - An unspecified error allows V8 script object wrappers
    to crash. (Issue #76771)

  - The included PDF functionality contains a garbage
    collection error. (Issue #78639)

  - Out-of-bounds read issues exist related to media
    buffers, mp3 files, box handling, Khmer characters,
    video handling, Tibetan characters, and triangle
    arrays. (Issues #82438, #85041, #89991, #90134, #90173,
    #95563, #95625)

  - An unspecified error allows data displayed in the URL
    to be spoofed. (Issue #83031)

  - Use-after-free errors exist related to unload event
    handling, the document loader, plugin handling, ruby,
    table style handling, and the focus controller.
    (Issues #89219, #89330, #91197, #92651, #94800, #93420,
    #93587)

  - The URL bar can be spoofed in an unspecified manner
    related to the forward button. (Issue #89564)

  - An NULL pointer error exists related to WebSockets.
    (Issue #89795)

  - An off-by-one error exists related to the V8 JavaScript
    engine. (Issue #91120)

  - A stale node error exists related to CSS stylesheet
    handling. (Issue #92959)

  - A cross-origin bypass error exists related to the V8
    JavaScript engine. (Issue #93416)

  - A double-free error exists related to XPath handling
    in libxml. (Issue #93472)

  - Incorrect permissions are assigned to non-gallery
    pages. (Issue #93497)

  - An improper string read occurs in the included PDF
    functionality. (Issue #93596)

  - An unspecified error allows unintended access to
    objects built in to the V8 JavaScript engine.
    (Issue #93906)

  - Self-signed certificates are not pinned properly.
    (Issue #95917)

  - A variable-type confusion issue exists in the V8
    JavaScript engine related to object sealing.
    (Issue #95920)");
  # http://googlechromereleases.blogspot.com/2011/09/stable-channel-update_16.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ce99226");

  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 14.0.835.163 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'14.0.835.163', severity:SECURITY_HOLE);

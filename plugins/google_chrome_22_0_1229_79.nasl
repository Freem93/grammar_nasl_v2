#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62313);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/02/03 17:40:02 $");

  script_cve_id(
    "CVE-2012-2874",
    "CVE-2012-2875",
    "CVE-2012-2876",
    "CVE-2012-2877",
    "CVE-2012-2878",
    "CVE-2012-2879",
    "CVE-2012-2880",
    "CVE-2012-2881",
    "CVE-2012-2882",
    "CVE-2012-2883",
    "CVE-2012-2884",
    "CVE-2012-2885",
    "CVE-2012-2886",
    "CVE-2012-2887",
    "CVE-2012-2888",
    "CVE-2012-2889",
    "CVE-2012-2890",
    "CVE-2012-2891",
    "CVE-2012-2892",
    "CVE-2012-2893",
    "CVE-2012-2894",
    "CVE-2012-2895",
    "CVE-2012-2897"
  );
  script_bugtraq_id(55676, 56457);
  script_osvdb_id(
    85749,
    85750,
    85751,
    85752,
    85753,
    85754,
    85755,
    85756,
    85757,
    85758,
    85759,
    85760,
    85761,
    85762,
    85763,
    85764,
    85765,
    85766,
    85767,
    85768,
    85770,
    85771,
    85775,
    93119,
    93120,
    93121,
    93122
  );

  script_name(english:"Google Chrome < 22.0.1229.79 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 22.0.1229.79 and is, therefore, affected by the following
vulnerabilities :

  - Out-of-bounds write errors exist related to Skia and
    the PDF viewer. (CVE-2012-2874, CVE-2012-2883,
    CVE-2012-2895)

  - Various, unspecified errors exist related to the PDF
    viewer. (CVE-2012-2875)

  - A buffer overflow error exists related to 'SSE2'
    optimizations. (CVE-2012-2876)

  - An unspecified error exists related to extensions and
    modal dialogs that can allow application crashes.
    (CVE-2012-2877)

  - Use-after-free errors exist related to plugin handling,
    'onclick' handling, 'SVG' text references and the PDF
    viewer. (CVE-2012-2878, CVE-2012-2887, CVE-2012-2888,
    CVE-2012-2890)

  - An error exists related to 'DOM' topology corruption.
    (CVE-2012-2879)

  - Race conditions exist in the plugin paint buffer.
    (CVE-2012-2880)

  - 'DOM' tree corruption can occur with plugins.
    (CVE-2012-2881)

  - A pointer error exists related to 'OGG' container
    handling. (CVE-2012-2882)

  - An out-of-bounds read error exists related to Skia.
    (CVE-2012-2884)

  - The possibility of a double-free error exists related to
    application exit. (CVE-2012-2885)

  - Universal cross-site scripting issues exist related
    to the v8 JavaScript engine bindings and frame
    handling. (CVE-2012-2886, CVE-2012-2889)

  - Address information can be leaked via inter process
    communication (IPC). (CVE-2012-2891)

  - A bypass error exists related to pop-up block.
    (CVE-2012-2892)

  - A double-free error exists related to 'XSL' transforms.
    (CVE-2012-2893)

  - An error exists related to graphics context handling.
    (CVE-2012-2894)

  - An unspecified memory corruption issue exists in the
    Windows 7 kernel, as used by Google Chrome.
    (CVE-2012-2897)

Successful exploitation of any of these issues could lead to an
application crash or even allow arbitrary code execution, subject to the
user's privileges.");
  # http://googlechromereleases.blogspot.com/2012/09/stable-channel-update_25.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe7996d2");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 22.0.1229.79 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'22.0.1229.79', severity:SECURITY_HOLE, xss:TRUE);

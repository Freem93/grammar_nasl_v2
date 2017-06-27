#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62861);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/10/03 03:33:27 $");

  script_cve_id(
    "CVE-2012-5116",
    "CVE-2012-5117",
    "CVE-2012-5119",
    "CVE-2012-5121",
    "CVE-2012-5122",
    "CVE-2012-5123",
    "CVE-2012-5124",
    "CVE-2012-5125",
    "CVE-2012-5126",
    "CVE-2012-5127",
    "CVE-2012-5128"
  );
  script_bugtraq_id(56413);
  script_osvdb_id(
    87071,
    87072,
    87073,
    87075,
    87076,
    87077,
    87078,
    87079,
    87081,
    87082,
    87083
  );

  script_name(english:"Google Chrome < 23.0.1271.64 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 23.0.1271.64 and is, therefore, affected by the following
vulnerabilities :

  - Use-after-free errors exist related to SVG filter
    handling, video layout, extension tab handling and
    plug-in placeholder handling. (CVE-2012-5116,
    CVE-2012-5121, CVE-2012-5125, CVE-2012-5126)

  - An error exists related to inappropriate SVG
    subresource loading in the 'img' context.
    (CVE-2012-5117)

  - A race condition exists related to 'Pepper' buffer
    handling. (CVE-2012-5119)

  - A bad cast error exists related to input handling.
    (CVE-2012-5122)

  - Out-of-bounds reads exist related to Skia.
    (CVE-2012-5123)

  - A memory corruption error exists related to texture
    handling. (CVE-2012-5124)

  - An integer overflow error exists related to 'WebP'
    handling. This error can lead to out-of-bounds reads.
    (CVE-2012-5127)

  - An improper write error exists related to the 'v8'
    JavaScript engine. (CVE-2012-5128)

Successful exploitation of any of these issues could lead to an
application crash or even allow arbitrary code execution, subject to the
user's privileges.");
  # http://googlechromereleases.blogspot.com/2012/11/stable-channel-release-and-beta-channel.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90289ffe");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 23.0.1271.64 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'23.0.1271.64', severity:SECURITY_WARNING);

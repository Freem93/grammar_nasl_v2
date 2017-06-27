#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56779);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/10/10 15:57:06 $");

  script_cve_id(
    "CVE-2011-3892",
    "CVE-2011-3893",
    "CVE-2011-3894",
    "CVE-2011-3895",
    "CVE-2011-3896",
    "CVE-2011-3897",
    "CVE-2011-3898"
  );
  script_bugtraq_id(50642);
  script_osvdb_id(77032, 77033, 77034, 77035, 77036, 77037, 77038, 94666);

  script_name(english:"Google Chrome < 15.0.874.120 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 15.0.874.120.  It is, therefore, potentially affected by the following
vulnerabilities :

    - A double-free error exists in the Theora decoder.
      (CVE-2011-3892)

    - Out-of-bounds read errors exist in the MVK and Vorbis
      media handlers. (CVE-2011-3893)

    - A memory corruption error exists in the VP8 decoding.
      (CVE-2011-3894)

    - A heap overflow error exists in the Vorbis decoder.
      (CVE-2011-3895)

    - A buffer overflow error exists in shader variable
      mapping functionality. (CVE-2011-3896)

    - A use-after-free error exists related to unspecified
      editing. (CVE-2011-3897)

    - In JRE7, applets are allowed to run without the
      proper permissions. (CVE-2011-3898)");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-147/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/267");
  # http://googlechromereleases.blogspot.com/2011/11/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f4e08a1");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 15.0.874.120 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/11");

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
google_chrome_check_version(installs:installs, fix:'15.0.874.120', severity:SECURITY_HOLE);

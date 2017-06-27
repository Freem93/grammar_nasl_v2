#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74434);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/10/03 03:33:27 $");

  script_cve_id(
    "CVE-2014-3154",
    "CVE-2014-3155",
    "CVE-2014-3156",
    "CVE-2014-3157"
  );
  script_bugtraq_id(67972, 67977, 67980, 67981);
  script_osvdb_id(107837, 107838, 107839, 107840);

  script_name(english:"Google Chrome < 35.0.1916.153 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 35.0.1916.153. It is, therefore, affected by the following
vulnerabilities :

  - Use-after-free errors exist in the file system API.
    (CVE-2014-3154)

  - An out-of-bounds read error exists related to SPDY.
    (CVE-2014-3155)

  - A buffer overflow error exits related to the clipboard.
    (CVE-2014-3156)

  - A heap overflow error exists related to media handling.
    (CVE-2014-3157)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://googlechromereleases.blogspot.ca/2014/06/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cbd2754b");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 35.0.1916.153 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'35.0.1916.153', severity:SECURITY_WARNING, xss:FALSE);

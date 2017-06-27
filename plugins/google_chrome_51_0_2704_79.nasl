#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91455);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/06/27 14:13:07 $");

  script_cve_id(
    "CVE-2016-1696",
    "CVE-2016-1697",
    "CVE-2016-1698",
    "CVE-2016-1699",
    "CVE-2016-1700",
    "CVE-2016-1701",
    "CVE-2016-1702",
    "CVE-2016-1703"
  );
  script_osvdb_id(139291, 139292, 139293, 139294, 139295, 139296, 139297);

  script_name(english:"Google Chrome < 51.0.2704.79 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 51.0.2704.79. It is, therefore, affected by multiple
vulnerabilities :

  - A cross-origin bypass issue exists in Extension
    bindings. No other details are available.
    (CVE-2016-1696)

  - A cross-origin bypass issue exists in Blink. No other
    details are available. (CVE-2016-1697)

  - An information disclosure vulnerability exists in
    Extension bindings. No other details are available.
    (CVE-2016-1698)

  - A flaw exists in DevTools due to a failure to sanitize
    a parameter. No other details are available.
    (CVE-2016-1699)

  - A use-after-free error exists in Extensions. No other
    details are available. (CVE-2016-1700)

  - A use-after-free error exists in Autofill. No other
    details are available. (CVE-2016-1701)

  - An out-of-bounds read error exists in Skia. No other
    details are available. (CVE-2016-1702)

  - Multiple unspecified issues exists that were found
    by internal auditing, fuzzing, etc. No other details
    are available. (CVE-2016-1703)");
  # http://googlechromereleases.blogspot.com/2016/06/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1853ec44");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 51.0.2704.79 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/03");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'51.0.2704.79', severity:SECURITY_HOLE);

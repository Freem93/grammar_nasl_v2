#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77184);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/10/03 03:33:27 $");

  script_cve_id("CVE-2014-3165", "CVE-2014-3166", "CVE-2014-3167");
  script_bugtraq_id(69201, 69202, 69203);

  script_name(english:"Google Chrome < 36.0.1985.143 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 36.0.1985.143. It is, therefore, affected by the following
vulnerabilities :

  - A use-after-free error exists in the Web Sockets
    implementation in Blink which allows remote attackers
    to cause a denial of service.
    (CVE-2014-3165)

  - An information disclosure vulnerability exists due to
    the Public Key Pinning (PKP) implementation not
    correctly considering the properties of SPDY
    connections. This error allows remote attackers to
    obtain sensitive information by leveraging the use of
    multiple domain names. (CVE-2014-3166)

  - Multiple unspecified vulnerabilities allow attackers to
    cause a denial of service.
    (CVE-2014-3167)");
  # http://googlechromereleases.blogspot.com/2014/08/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53a4c8be");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 36.0.1985.143 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/13");

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

google_chrome_check_version(installs:installs, fix:'36.0.1985.143', severity:SECURITY_WARNING, xss:FALSE);

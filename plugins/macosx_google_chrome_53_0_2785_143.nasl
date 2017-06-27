#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93818);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id("CVE-2016-5177", "CVE-2016-5178");
  script_bugtraq_id(93238);
  script_osvdb_id(144925, 144926, 144927);

  script_name(english:"Google Chrome < 53.0.2785.143 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Mac OS X host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 53.0.2785.143. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified use-after-free error exists in V8 that
    allows an unauthenticated, remote attacker to deference
    already freed memory, resulting in the execution of
    arbitrary code. (CVE-2016-5177)

  - Multiple flaws exist that allow an attacker to cause an
    unspecified impact. No other details are available.
    (CVE-2016-5178)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://googlechromereleases.blogspot.com/2016/09/stable-channel-update-for-desktop_29.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?df8742a0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 53.0.2785.143 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/30");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'53.0.2785.143', severity:SECURITY_HOLE);

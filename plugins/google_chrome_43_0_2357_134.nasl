#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84731);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/08/16 04:40:05 $");

  script_cve_id("CVE-2015-5122", "CVE-2015-5123");
  script_bugtraq_id(75710, 75712);
  script_osvdb_id(124416, 124424);
  script_xref(name:"CERT", value:"338736");
  script_xref(name:"CERT", value:"918568");

  script_name(english:"Google Chrome < 43.0.2357.134 Multiple RCE Vulnerabilities");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 43.0.2357.134. It is, therefore, affected by multiple remote
code execution vulnerabilities in the bundled version of Adobe Flash :

  - A use-after-free error exists in the opaqueBackground
    class in the ActionScript 3 (AS3) implementation. A
    remote attacker, via specially crafted Flash content,
    can dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2015-5122)

  - A use-after-free error exists in the BitmapData class in
    the ActionScript 3 (AS3) implementation. A remote
    attacker, via specially crafted Flash content, can
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2015-5123)");
  script_set_attribute(attribute:"see_also",value:"https://helpx.adobe.com/security/products/flash-player/apsb15-18.html");
  # http://googlechromereleases.blogspot.com/2015/07/stable-channel-update_14.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8156ecbe");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 43.0.2357.134 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash opaqueBackground Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/07/10");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'43.0.2357.134', severity:SECURITY_HOLE);

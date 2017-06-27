#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91716);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/08/02 13:41:58 $");

  script_cve_id("CVE-2016-1704");
  script_osvdb_id(140128, 140129, 140130);

  script_name(english:"Google Chrome < 51.0.2704.103 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 51.0.2704.103. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists in the individualCharacterRanges()
    function in CachingWordShaper.cpp that is triggered when
    handling invalid glyph shaping results. A remote
    attacker can exploit this issue to corrupt memory,
    resulting in the execution of code. (VulnDB 140128)

  - A use-after-free error exists in the OnChannelMessage()
    function in node_channel.cc that allows a remote
    attacker to dereference already freed memory, resulting
    in the execution of arbitrary code. (VulnDB 140129)

  - An unspecified flaw exists in
    shared_worker_devtools_manager.cc that allows a remote
    attacker to have an unspecified impact. (VulnDB 140130)");
  # https://googlechromereleases.blogspot.com/2016/06/stable-channel-update_16.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0892ec7f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 51.0.2704.103 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/20");

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

google_chrome_check_version(installs:installs, fix:'51.0.2704.103', severity:SECURITY_HOLE);

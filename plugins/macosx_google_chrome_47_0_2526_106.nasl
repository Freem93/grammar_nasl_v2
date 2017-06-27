#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87418);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_cve_id("CVE-2015-6792");
  script_osvdb_id(131843, 131844);

  script_name(english:"Google Chrome < 47.0.2526.106 Multiple RCE (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 47.0.2526.106. It is, therefore, affected by multiple
vulnerabilities.

  - The WebCursor::Deserialize() method in file
    common/cursors/webcursor.cc. is affected by an integer
    overflow condition that allows an attacker to execute
    arbitrary code. (VulnDB 131843)

  - The MidiManagerAlsa::DispatchSendMidiData() method in
    file media/midi/midi_manager_alsa.cc contains a
    unspecified flaw that allows an attacker to execute
    arbitrary code outside of sandbox restrictions.
    (VulnDB 131844)");
  # http://googlechromereleases.blogspot.com/2015/12/stable-channel-update_15.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?b00a2b47");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 47.0.2526.106 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'47.0.2526.106', severity:SECURITY_HOLE);

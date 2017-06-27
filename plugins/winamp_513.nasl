#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20826);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2011/09/26 16:36:05 $");

  script_cve_id("CVE-2005-3188", "CVE-2006-0476");
  script_bugtraq_id(16410, 16462);
  script_osvdb_id(22789, 22975);

  script_name(english:"Winamp < 5.13 Playlist Handling Multiple Overflows");
  script_summary(english:"Checks for multiple buffer overflow vulnerabilities in Winamp < 5.13"); 
 
  script_set_attribute(attribute:"synopsis", value:
"A multimedia application that is vulnerable to multiple buffer
overflows is installed on the remote Windows host." );
  script_set_attribute(attribute:"description", value:
"The remote host is using Winamp, a popular media player for Windows. 

It's possible that a remote attacker using a specially crafted M3U or
PLS file can cause a buffer overflow in the version of Winamp
installed on the remote Windows host, resulting in a crash of the
application and even execution of arbitrary code remotely subject to
the user's privileges.  Note that these issues can reportedly be
exploited without user interaction by linking to a '.pls' file in an
IFRAME tag." );
  script_set_attribute(attribute:"see_also", value:"http://www.vupen.com/exploits/20060129.winamp0day.c.php" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?215564e1" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25ab0f36" );
  script_set_attribute(attribute:"see_also", value:"http://www.winamp.com/player/version-history" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Winamp version 5.13 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Winamp Playlist UNC Path Computer Name Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/31");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Winamp/Version");
if (version =~ "^([0-4]\.|5\.(0\.|1\.[0-2]([^0-9]|$)))")
{
  if (report_verbosity > 0)
  {
    fixed_version = '5.13';

    path = get_kb_item("SMB/Winamp/Path");
    if (isnull(path)) path = 'n/a';

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Winamp " + version + " is installed.");

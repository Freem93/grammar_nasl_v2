#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15789);
 script_version("$Revision: 1.21 $");

 script_cve_id("CVE-2004-1094");
 script_bugtraq_id(11555);
 script_osvdb_id(19906);
 
 script_name(english:"RealPlayer Skin File Remote Buffer Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by a remote buffer
overflow." );
 script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer /
RealOne Player for Windows may allow an attacker to execute arbitrary
code on the remote host, with the privileges of the user running
RealPlayer because of an overflow vulnerability in the third-party
compression library 'DUNZIP32.DLL'. 

To do so, an attacker would need to send a corrupted skin file (.RJS)
to a remote user and have him open it using RealPlayer." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Oct/1044" );
 script_set_attribute(attribute:"see_also", value:"http://service.real.com/help/faq/security/041026_player/EN/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade according to the vendor advisory referenced above." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/27");
 script_cvs_date("$Date: 2016/11/02 14:37:09 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/10/27");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
script_end_attributes();

 script_summary(english:"Checks RealPlayer build number");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("realplayer_detect.nasl");
 script_require_keys("SMB/RealPlayer/Product", "SMB/RealPlayer/Build");
 exit(0);
}

include("global_settings.inc");


# nb: RealOne Player is also affected, but we don't currently know 
#     which specific build number addresses the issue.
prod = get_kb_item("SMB/RealPlayer/Product");
if (!prod || prod != "RealPlayer") exit(0);


# Check build.
build = get_kb_item("SMB/RealPlayer/Build");
if (build)
{
  # There's a problem if the build is:
  #  - [6.0.12.0, 6.0.12.1056), Real Player
  ver = split(build, sep:'.', keep:FALSE);
  if (
    int(ver[0]) < 6 ||
    (
      int(ver[0]) == 6 &&
      int(ver[1]) == 0 &&
      (
        int(ver[2]) < 12 ||
        (int(ver[2]) == 12 && int(ver[3]) < 1056)
      )
    )
  )
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        prod, " build ", build, " is installed on the remote host.\n"
      );
      security_hole(port:get_kb_item("SMB/transport"), extra:report);
    }
    else security_hole(get_kb_item("SMB/transport"));
  }
}

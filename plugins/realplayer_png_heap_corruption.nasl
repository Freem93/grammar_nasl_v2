#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11496);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2003-0141");  
 script_bugtraq_id(7177);
 script_osvdb_id(11768);
 
 script_name(english:"RealPlayer PNG Deflate Algorithm Heap Corruption Arbitrary Code Execution");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by a heap corruption
vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer /
RealOne Player / RealPlayer Enterprise for Windows has a flaw in the
remote version that may allow an attacker to execute arbitrary code on
the remote host, with the privileges of the user running RealPlayer. 

To do so, an attacker would need to send a corrupted PNG file to a
remote user and have him open it using RealPlayer." );
 script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/common/showdoc.php?idx=311&idxseccion=10" );
 script_set_attribute(attribute:"see_also", value:"http://service.real.com/help/faq/security/securityupdate_march2003.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade according to the vendor advisories referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/03/28");
 script_cvs_date("$Date: 2011/04/13 17:53:39 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
script_end_attributes();

 
 script_summary(english:"Checks RealPlayer build number");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("realplayer_detect.nasl");
 script_require_keys("SMB/RealPlayer/Product", "SMB/RealPlayer/Build");
 exit(0);
}

#

include("global_settings.inc");


prod = get_kb_item("SMB/RealPlayer/Product");
if (
  prod &&
  (prod == "RealPlayer" || prod == "RealOne Player")
) {
  # Check RealPlayer build.
  build = get_kb_item("SMB/RealPlayer/Build");
  if (build)
  {
    # There's a problem if the build is:
    #  - [6.0.9.0, 6.0.9.584], RealPlayer 8
    #  - [6.0.10.0, 6.0.10.505], RealOne Player
    #  - [6.0.11.0, 6.0.11.774], RealOne Enterprise
    #  - [6.0.11.818, 6.0.11.853], RealOne Player version 2
    ver = split(build, sep:'.', keep:FALSE);
    if (
      int(ver[0]) < 6 ||
      (
        int(ver[0]) == 6 &&
        int(ver[1]) == 0 &&
        (
          int(ver[2]) < 8 ||
          (prod == "RealPlayer" &&         int(ver[2]) == 9 && int(ver[3]) <= 584) ||
          (prod == "RealOne Player" &&     int(ver[2]) == 10 && int(ver[3]) <= 505) ||
          (prod == "RealOne Enterprise" && int(ver[2]) == 11 && int(ver[3]) <= 774) ||
          (prod == "RealOne Player" &&     int(ver[2]) == 11 && int(ver[3]) >= 818 && int(ver[3]) <= 853)
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
}

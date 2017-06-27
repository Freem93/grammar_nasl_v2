#
#  (C) Tenable Network Security, Inc.
# 
# - Thanks to stbjr -


include("compat.inc");

if(description)
{
 script_id(12044);
 script_version("$Revision: 1.19 $");

 script_cve_id("CVE-2004-0258", "CVE-2004-0273");
 script_bugtraq_id(9579, 9580);
 script_osvdb_id(3827, 6616);
 
 script_name(english:"RealPlayer File Handler Arbitrary Code Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by several remote flaws." );
 script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer /
RealOne Player / RealPlayer Enterprise has a flaw that may allow an
attacker to execute arbitrary code on the remote host, with the
privileges of the user running RealPlayer, using specially crafted RP,
RT, RAM, RPM or SMIL files. 

In addition, it may allow an attacker to download and execute
arbitrary code on the affected system using specially crafted RMP
files." );
 script_set_attribute(attribute:"see_also", value:"http://www.ngssoftware.com/advisories/realone.txt" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Feb/477" );
 script_set_attribute(attribute:"see_also", value:"http://service.real.com/help/faq/security/040123_player/EN/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade according to the vendor advisories referenced above." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/04");
 script_cvs_date("$Date: 2016/11/02 14:37:09 $");
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


# nb: RealOne Player and RealPlayer Enterprise are also affected,
#     but we don't currently know which specific build numbers
#     address the issues.
prod = get_kb_item("SMB/RealPlayer/Product");
if (!prod || prod != "RealPlayer") exit(0);


# Check build.
build = get_kb_item("SMB/RealPlayer/Build");
if (build)
{
  # There's a problem if the build is:
  #  - [6.0.11.0, 6.0.11.872), RealOne Player
  #  - [6.0.12.0, 6.0.12.690), Real Player
  ver = split(build, sep:'.', keep:FALSE);
  if (
    int(ver[0]) < 6 ||
    (
      int(ver[0]) == 6 &&
      int(ver[1]) == 0 &&
      (
        int(ver[2]) < 11 ||
        (int(ver[2]) == 11 && int(ver[3]) < 872) ||
        (int(ver[2]) == 12 && int(ver[3]) < 690)
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

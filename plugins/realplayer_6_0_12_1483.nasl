#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21140);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-2922", "CVE-2005-2936", "CVE-2006-0323", "CVE-2006-1370");
  script_bugtraq_id(15448, 17202);
  script_osvdb_id(21010, 24061, 24062, 24063);

  script_name(english:"RealPlayer for Windows < Build 6.0.12.1483 Multiple Vulnerabilities");
  script_summary(english:"Checks RealPlayer build number");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by several issues." );
 script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer /
RealOne Player / RealPlayer Enterprise on the remote Windows host
suffers from one or more buffer overflows involving maliciously-
crafted SWF and MBC files as well as web pages.  In addition, it also
may be affected by a local privilege escalation issue." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d16d359" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0b66183" );
 script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/03162006_player/en/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade according to the vendor advisory referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/15");
 script_cvs_date("$Date: 2011/09/12 01:34:03 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/03/16");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

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
if (!build) exit(0);

# There's a problem if the build is before 6.0.12.1483.
ver = split(build, sep:'.', keep:FALSE);
if (
  int(ver[0]) < 6 ||
  (
    int(ver[0]) == 6 &&
    int(ver[1]) == 0 && 
    (
      int(ver[2]) < 12 ||
      (int(ver[2]) == 12 && int(ver[3]) < 1483)
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

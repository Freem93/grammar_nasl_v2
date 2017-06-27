#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14278);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2011/09/12 01:34:03 $");

 script_cve_id("CVE-2004-0550");
 script_bugtraq_id(10527, 10528, 10934);
 script_osvdb_id(6851, 61196);

 script_name(english:"RealPlayer Multiple Remote Overflows");
 script_summary(english:"Checks RealPlayer build number");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by several remote
overflows.");
 script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer on
the remote host is vulnerable to several overflows.  In exploiting
these flaws, an attacker would need to be able to coerce a local user
into visiting a malicious URL or downloading a malicious media file
which, on execution, would execute code with the privileges of the
local user.");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/365709/2004-06-07/2004-06-13/0");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a2e2a79");
 script_set_attribute(attribute:"see_also", value:"http://service.real.com/help/faq/security/040610_player/EN/");
 script_set_attribute(attribute:"see_also", value:"http://www.eeye.com/html/research/upcoming/20040811.html");
 script_set_attribute(attribute:"solution", value:
"Install the updates as outlined in the vendor advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/16");
 script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/06/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
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
  ver = split(build, sep:'.', keep:FALSE);
  if (
    int(ver[0]) == 6 && int(ver[1]) == 0 && 
    (
      (int(ver[2]) == 10 && int(ver[3]) == 505) ||
      (
        int(ver[2]) == 11 && 
        (int(ver[3]) >= 818 && int(ver[3]) <= 872)
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

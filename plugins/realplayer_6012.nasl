#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20184);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2011/04/13 17:53:39 $");

  script_cve_id("CVE-2005-2629", "CVE-2005-2630", "CVE-2005-3677");
  script_bugtraq_id(15381, 15382, 15383, 15398);
  script_osvdb_id(18827, 20773);

  script_name(english:"RealPlayer for Windows Multiple Overflows");
  script_summary(english:"Checks RealPlayer build number");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by several overflow
vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer /
RealOne Player / RealPlayer Enterprise for Windows on the remote host
is affected by multiple buffer overflow vulnerabilities. 

An attacker may be able to leverage these issues to execute arbitrary
code on the remote host subject to the permissions of the user running
the affected application.  Note that a user doesn't necessarily need
to explicitly access a malicious media file since the browser may
automatically pass to the application RealPlayer skin files (ie, files
with the extension '.rjs')." );
  script_set_attribute(attribute:"see_also", value:"http://research.eeye.com/html/advisories/published/AD20051110a.html" );
  script_set_attribute(attribute:"see_also", value:"http://research.eeye.com/html/advisories/published/AD20051110b.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/416475" );
  script_set_attribute(attribute:"see_also", value:"http://service.real.com/help/faq/security/security111005.html" );
  script_set_attribute(attribute:"see_also", value:"http://service.real.com/help/faq/security/051110_player/EN/" );
  script_set_attribute(attribute:"solution", value:
"Upgrade according to the vendor advisories referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/11");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/10");
  script_set_attribute(attribute:"patch_publication_date", value: "2005/11/10");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

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
  # There's a problem if the build is 6.0.12.1235 or older.
  ver = split(build, sep:'.', keep:FALSE);
  if (
    int(ver[0]) < 6 ||
    (
      int(ver[0]) == 6 &&
      int(ver[1]) == 0 && 
      (
        int(ver[2]) < 12 ||
        (int(ver[2]) == 12 && int(ver[3]) <= 1235)
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

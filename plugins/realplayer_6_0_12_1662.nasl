#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(27591);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2007-2263", "CVE-2007-2264", "CVE-2007-3410",
                "CVE-2007-4599", "CVE-2007-5080", "CVE-2007-5081");
  script_bugtraq_id(24658, 26214, 26284);
  script_osvdb_id(37374, 38339, 38340, 38341, 38342, 38343, 38344);

  script_name(english:"RealPlayer for Windows < Build 6.0.12.1662 Multiple Vulnerabilities");
  script_summary(english:"Checks RealPlayer build number");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by several buffer overflow
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer /
RealOne Player / RealPlayer Enterprise on the remote Windows host
suffers from several buffer overflows involving specially crafted
media files (eg, '.mp3', '.rm', '.SMIL', '.swf', '.ram', and '.pls'). 
If an attacker can trick a user on the affected system into opening
such a file or browsing to a specially crafted web page, he may be
able to exploit one of these issues to execute arbitrary code subject
to the user's privileges on the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/482855/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/482856/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/482942/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Oct/922" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Oct/924" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Oct/925" );
 script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/10252007_player/en/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to RealPlayer 10.5 build 6.0.12.1662 / RealPlayer Enterprise
build 6.0.11.2160 or later. 

Note that the vendor's advisory states that build numbers for
RealPlayer 10.5 are not sequential." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(119, 189);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/26");
 script_cvs_date("$Date: 2016/12/09 20:54:57 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/10/05");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("realplayer_detect.nasl");
  script_require_keys("SMB/RealPlayer/Product", "SMB/RealPlayer/Build");

  exit(0);
}


include("global_settings.inc");


prod = get_kb_item("SMB/RealPlayer/Product");
if (!prod) exit(0);


build = get_kb_item("SMB/RealPlayer/Build");
if (!build) exit(0);

ver = split(build, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);


vuln = FALSE;
if ("RealPlayer" == prod)
{
  # nb: build numbers ARE NOT NECESSARILY SEQUENTIAL!
  if (
    ver[0] < 6 ||
    (
      ver[0] == 6 && ver[1] == 0 && 
      (
        ver[2] < 12 ||
        (
          ver[2] == 12 && 
          (
            ver[3] <= 1578 ||
            ver[3] == 1698 ||
            ver[3] == 1741
          )
        )
      )
    )
  ) vuln = TRUE;
}
else if ("RealPlayer Enterprise" == prod)
{
  # Fix is 6.0.11.2160 per 
  # <http://service.real.com/realplayer/security/security/enterprise_102507.html>.
  if (
    ver[0] < 6 ||
    (
      ver[0] == 6 && ver[1] == 0 && 
      (
        ver[2] < 11 ||
        (ver[2] == 11 && ver[3] < 2160)
      )
    )
  ) vuln = TRUE;
}
else if ("RealOne Player" == prod)
{
  vuln = TRUE;
}


if (vuln)
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

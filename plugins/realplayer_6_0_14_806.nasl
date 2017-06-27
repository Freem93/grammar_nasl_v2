#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33744);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/09 20:54:57 $");

  script_cve_id("CVE-2007-5400", "CVE-2008-1309", "CVE-2008-3064", "CVE-2008-3066");
  script_bugtraq_id(28157, 30370, 30376, 30378, 30379);
  script_osvdb_id(42946, 47138, 48286, 48287);
  script_xref(name:"Secunia", value:"27620");
  script_xref(name:"Secunia", value:"29315");

  script_name(english:"RealPlayer for Windows < Build 6.0.14.806 / 6.0.12.1675 Multiple Vulnerabilities");
  script_summary(english:"Checks RealPlayer build number");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by at least one security
vulnerability." );
  script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer /
on the remote Windows host suffers from possibly several issues :

  - Heap memory corruption issues in several ActiveX 
    controls can lead to arbitrary code execution.
    (CVE-2008-1309)

  - An unspecified local resource reference vulnerability.
    (CVE-2008-3064)

  - An SWF file heap-based buffer overflow. (CVE-2007-5400)

  - A buffer overflow involving the 'import()' method in an
    ActiveX control implemented by the 'rjbdll.dll' module 
    could result in arbitrary code execution.
    (CVE-2008-3066)

Note that RealPlayer 11 (builds 6.0.14.738 - 6.0.14.802) are only affected
by the first issue (CVE-2008-1309)." );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Mar/156" );
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2007-93/advisory/" );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-046" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/494778/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-047" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/494779/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Jul/538" );
  script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/07252008_player/en/" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to RealPlayer 11.0.3 (build 6.0.14.806) / RealPlayer 10.5
(build 6.0.12.1675) or later. 

Note that the vendor's advisory states that build numbers for
RealPlayer 10.5 are not sequential." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'RealPlayer rmoc3260.dll ActiveX Control Heap Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119, 264, 399);
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/28");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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
            ver[3] <= 1663 ||
            ver[3] == 1698 ||
            ver[3] == 1741
          )
        ) ||
        (ver[2] == 14 && ver[3] < 806)
      )
    )
  ) vuln = TRUE;
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

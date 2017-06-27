#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25172);
  script_version("$Revision: 1.14 $");

  script_bugtraq_id(23866);
  script_osvdb_id(35789);
  script_cve_id("CVE-2007-2508");

  script_name(english:"Trend Micro ServerProtect EarthAgent RPC Request Remote Buffer Overflow");
  script_summary(english:"Checks version of ServerProtect"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to a remote buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote version of Trend Micro ServerProtect is vulnerable to a
stack overflow involving its EarthAgent service.  An unauthenticated,
remote attacker may be able to leverage this issue with specially-
crafted RPC requests to execute arbitrary code on the remote host. 

Note that by default, Trend Micro services run with LocalSystem
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-024.html" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/May/97" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9dc8993" );
 script_set_attribute(attribute:"solution", value:
"Apply Security Patch 2 - Build 1174 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Trend Micro ServerProtect 5.58 EarthAgent.EXE Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/08");
 script_cvs_date("$Date: 2016/11/03 20:40:07 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/04/03");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:trend_micro:serverprotect:5.58 and previous versions");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_dependencies("trendmicro_serverprotect_detect.nasl");
  script_require_keys("Antivirus/TrendMicro/ServerProtect");
  script_require_ports(3628);

  exit(0);
}


port = 5168;


# Check the version number.
ver = get_kb_item ("Antivirus/TrendMicro/ServerProtect");
if (ver)
{
 iver = split (ver, sep:".", keep:FALSE);
 for (i=0; i<max_index(iver); i++)
   iver[i] = int(iver[i]);

 # Versions before 5.5 build 1174 are affected.
 if (
      iver[0] < 5 ||
      (
        iver[0] == 5 &&
        (
          iver[1] < 58 ||
          (iver[1] == 58 && iver[2] == 0 && iver[3] < 1174)
        )
      )
    ) security_hole(port);
}

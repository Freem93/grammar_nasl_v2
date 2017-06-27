#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25171);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2007-2528");
  script_bugtraq_id(23868);
  script_osvdb_id(35793);

  script_name(english:"Trend Micro ServerProtect AgRpcCln.dll Buffer Overflow");
  script_summary(english:"Checks version of ServerProtect"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to a remote buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote version of Trend Micro ServerProtect is vulnerable to a
stack overflow involving the 'wcscpy' function of the routine
'CAgRpcClient::CreateBinding' in AgRpcCln.dll library.  An
unauthenticated, remote attacker may be able to leverage this issue
with specially crafted RPC requests to its SpntSvc.exe daemon to
execute arbitrary code on the remote host. 

Note that by default, Trend Micro services run with LocalSystem
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-025.html" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/May/89" );
  # http://www.trendmicro.com/ftp/documentation/readme/spnt_558_win_en_securitypatch3_readme.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b7dccdd" );
 script_set_attribute(attribute:"solution", value:
"Apply Security Patch 3 - Build 1176 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Trend Micro ServerProtect 5.58 CreateBinding() Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/08");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/04/13");
 script_cvs_date("$Date: 2016/11/03 20:40:07 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:trend_micro:serverprotect");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_dependencies("trendmicro_serverprotect_detect.nasl");
  script_require_keys("Antivirus/TrendMicro/ServerProtect");
  script_require_ports(5168);

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

 # Versions before 5.5 build 1176 are affected.
 if (
      iver[0] < 5 ||
      (
        iver[0] == 5 &&
        (
          iver[1] < 58 ||
          (iver[1] == 58 && iver[2] == 0 && iver[3] < 1176)
        )
      )
    ) security_hole(port);
}

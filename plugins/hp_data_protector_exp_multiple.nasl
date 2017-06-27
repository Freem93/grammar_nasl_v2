#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49645);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2010-3007", "CVE-2010-3008");
  script_bugtraq_id(43105, 43113);
  script_osvdb_id(67973, 67975);
  script_xref(name:"Secunia",value:"41361");

  script_name(english:"HP Data Protector Express < 4.x build 56906 / 3.x build 56936 Multiple Vulnerabilities");
  script_summary(english:"Checks version of dpwinsdr.exe");
 
  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Windows host contains an application that is affected by a
multiple remote vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"HP Data Protector Express is installed on the remote host.  The
installed version of the software is affected by multiple remote
vulnerabilities including a buffer overflow and a NULL pointer
deference.  An attacker could leverage these vulnerabilities to
execute remote code or cause a denial of service attack on the
affected host."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-174/");

  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-175/");

  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2010/Sep/62");

  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docLocale=en&docId=emr_na-c02498535-1
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?fc845837");

  script_set_attribute(attribute:"solution", value:"Install HP Data Protector Express 4.0 SP1 build 56906 / 3.5 SP2 build 56936 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP Data Protector DtbClsLogin Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value: "2010/09/08");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/22");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:data_protector_express");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_data_protector_exp_installed.nasl");
  script_require_keys("SMB/HP Data Protector Express/Path", "SMB/HP Data Protector Express/Version", "SMB/HP Data Protector Express/Build");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit('SMB/HP Data Protector Express/Path');
version = get_kb_item_or_exit('SMB/HP Data Protector Express/Version');
build = get_kb_item_or_exit('SMB/HP Data Protector Express/Build');

ver = split(version, sep:'.');
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = NULL;
if ((ver[0] == 3 && ver[1] < 50) ||
    (ver[0] == 3 && ver[1] == 50 && build < 56936)) fix = '3.50 build 56936';
else if (ver[0] == 4 && ver[1] == 0 && build < 56906) fix = '4.0 build 56906';

if (fix)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version + ' build ' + build +
      '\n  Fixed version     : ' + fixed_version + '\n';
      security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}
exit(0, "The HP Data Protector Express "+version+" Build "+build+" install in "+path+" is not affected.");

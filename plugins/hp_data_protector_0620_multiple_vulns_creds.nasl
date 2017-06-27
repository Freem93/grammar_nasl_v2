#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(55551);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/18 20:40:53 $");

  script_cve_id(
    "CVE-2011-1514",
    "CVE-2011-1515",
    "CVE-2011-1865", 
    "CVE-2011-1866"
  );
  script_bugtraq_id(48486, 48488);
  script_osvdb_id(
    73569,
    73570,
    73571,
    73572
);
  script_xref(name:"Secunia", value:"45100");

  script_name(english:"HP Data Protector <= A.06.20 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks if encrypted control communication services is enabled.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP Data Protector installed on the remote Windows host
is affected by one or more of the following vulnerabilities :

  - Multiple denial of service vulnerabilities exist in the
    'data protect inet' service. (CVE-2011-1514, 
    CVE-2011-1515)

  - A buffer overflow vulnerability exists in the 'data
    protector inet' service that can be exploited via 
    EXEC_CMD. (CVE-2011-1864)

  - A buffer overflow vulnerability exists in the inet
    service that could result in code execution via a 
    request containing crafted parameters. (CVE-2011-1865)");

  # http://www.coresecurity.com/content/HP-Data-Protector-EXECCMD-Vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1ae3e63");
  # http://www.coresecurity.com/content/HP-Data-Protector-multiple-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5807534");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02872182
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e38ce76");
  script_set_attribute(attribute:"solution", value:
"1. Upgrade to Data Protector A.06.20 or later and

2. Enable encrypted control communication services on cell server and
   all clients in cell.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-076");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP OmniInet.exe Opcode 20 Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_data_protector_installed_local.nasl");
  script_require_keys("SMB/HP Data Protector/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('SMB/HP Data Protector/Version');
encrypted_comm = get_kb_item_or_exit('SMB/HP Data Protector/Encrypted');
verui = get_kb_item('SMB/HP Data Protector/VersionUI');
type = get_kb_item('SMB/HP Data Protector/Type');
path = get_kb_item('SMB/HP Data Protector/Path');

if (encrypted_comm) encrypted_comm = 'True';
else encrypted_comm = 'False';

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 6 || 
  (ver[0] == 6 && ver[1] < 20) ||
  (ver[0] == 6 && ver[1] == 20 && encrypted_comm == 'False')
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path + 
      '\n  Install type      : ' + type +
      '\n  Encryption        : ' + encrypted_comm + 
      '\n  Installed version : ' + verui +
      '\n  Fixed version     : A.06.20 with encrypted control communications services \n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}
else exit(0, 'The HP Data Protector '+verui+' install is not affected.');

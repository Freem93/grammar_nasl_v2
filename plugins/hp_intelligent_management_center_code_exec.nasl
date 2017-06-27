#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(54628);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/01/19 01:10:18 $");

  script_cve_id(
    "CVE-2011-1848",
    "CVE-2011-1849",
    "CVE-2011-1850",
    "CVE-2011-1851",
    "CVE-2011-1852",
    "CVE-2011-1853",
    "CVE-2011-1854"
  );
  script_bugtraq_id(47789);
  script_osvdb_id(
    72391,
    72392,
    72393,
    72394,
    72395,
    72396,
    72397
  );
  script_xref(name:'Secunia', value:'44556');

  script_name(english:'HP Intelligent Management Center < 5.0 E0101-L02 Multiple Vulnerabilities');
  script_summary(english:'Checks version of HP Intelligent Management Center');

  script_set_attribute(attribute:'synopsis', value:
'The remote Windows host has an application installed that is affected
by multiple vulnerabilities.');

  script_set_attribute(attribute:'description', value:
'According to its version number, the HP Intelligent Management Center
install on the remote host is potentially affected by multiple
vulnerabilities :

  - A stack-based buffer overflow vulnerability exists in
    the \'img.exe\' component. (CVE-2011-1848)

  - A flaw exists in the \'tftpserver.exe\' component which
    could allow arbitrary file creation when handling WRQ
    opcode types. (CVE-2011-1849)

  - A stack-based buffer overflow vulnerability exists in 
    the \'dbman.exe\' component. (CVE-2011-1850)

  - A stack-based buffer overflow vulnerability exists in
    the \'tftpserver.exe\' component. (CVE-2011-1851)

  - A stack-based buffer overflow vulnerability exists in
    the \'tftpserver.exe\' component. (CVE-2011-1852)

  - A buffer overflow vulnerability exists in the 
    \'tftpserver.exe\' component when handling a large or
    invalid opcode word of a packet. (CVE-2011-1853)

  - A use-after-free vulnerability exists in the 
    \'imcsyslogdm.exe\' component. (CVE-2011-1854)');

  script_set_attribute(attribute:'see_also', value:'http://www.nessus.org/u?cd59d8c8');
  script_set_attribute(attribute:'see_also', value:'http://www.zerodayinitiative.com/advisories/ZDI-11-160');
  script_set_attribute(attribute:'see_also', value:'http://www.zerodayinitiative.com/advisories/ZDI-11-161');
  script_set_attribute(attribute:'see_also', value:'http://www.zerodayinitiative.com/advisories/ZDI-11-162');
  script_set_attribute(attribute:'see_also', value:'http://www.zerodayinitiative.com/advisories/ZDI-11-163');
  script_set_attribute(attribute:'see_also', value:'http://www.zerodayinitiative.com/advisories/ZDI-11-164');
  script_set_attribute(attribute:'see_also', value:'http://www.zerodayinitiative.com/advisories/ZDI-11-165');
  script_set_attribute(attribute:'see_also', value:'http://www.zerodayinitiative.com/advisories/ZDI-11-166');
  script_set_attribute(attribute:'solution', value:'Upgrade to HP Intelligent Management Center 5.0 E0101-L02 or later.');
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/24");

  script_set_attribute(attribute:'plugin_type', value:'local');
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies('hp_intelligent_management_center_installed.nasl');
  script_require_keys('SMB/HP_iMC/installed');
  
  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

version = get_kb_item_or_exit('SMB/HP_iMC/version');
path = get_kb_item_or_exit('SMB/HP_iMC/path');

if (version =~ '^([0-4]\\.|5\\.0([^-]|-E0101([^;]|$|;L0[01]($|[^0-9]))))')
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.0-E0101;L02\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
}
else exit(0, 'HP Intelligent Management Center version '+version+' is installed and thus is not affected.');

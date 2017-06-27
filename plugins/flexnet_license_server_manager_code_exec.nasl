#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(58273);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/20 14:02:59 $");

  script_cve_id("CVE-2011-1389", "CVE-2011-4135");
  script_bugtraq_id(49191, 52718);
  script_osvdb_id(74610, 81899);
  script_xref(name:"EDB-ID", value:"18877");

  script_name(english:"FlexNet License Multiple Vulnerabilities");
  script_summary(english:"Checks version of lmgrd.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a license management application
installed that allows execution of arbitrary code.");
  script_set_attribute(attribute:"description", value:
"The version of FlexNet License Manager installed on the remote
Windows host is earlier than 11.10.0.3. As such, it is potentially
affected by multiple vulnerabilities :

- Multiple problems exist that allow an attacker to

influence the saving and loading of log files on the

server. By utilizing a directory traversal issue and

some file renaming bugs, an attacker can leverage these

vulnerabilities to execute arbitrary code subject to

the user running the affected application.

- A buffer overflow vulnerability exists that coul lead to

arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/lmgrd_1-adv.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-272/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-052/");
  script_set_attribute(attribute:"see_also", value:"http://www.flexerasoftware.com/pl/13057.htm");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21577760");
  script_set_attribute(attribute:"solution", value:
"If using IBM Rational License Key Server, apply the vendor-supplied
hotfix.

Otherwise, upgrade the FlexNet lmgrd License Server Manager to
11.10.0.3 / 11.10.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'FlexNet License Server Manager lmgrd Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("flexnet_license_server_detect.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Flexera FlexNet License Server/Version", "SMB/Flexera FlexNet License Server/Path");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

version = get_kb_item_or_exit('SMB/Flexera FlexNet License Server/Version');
path = get_kb_item_or_exit('SMB/Flexera FlexNet License Server/Path');
service = get_kb_item('SMB/Flexera FlexNet License Server/Service');
if (isnull(service)) service = 'FLEXlm License Manager';

# Unless we're paranoid, make sure the service is running
if (report_paranoia < 2)
{
  status = get_kb_item('SMB/svc/'+service);
  if (status != SERVICE_ACTIVE)
    exit(0, 'The FlexNet License Manager is installed but not active.');
}

fix = '11.10.0.3';
if (ver_compare(ver:version, fix:fix) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  File              : ' + path + '\\lmgrd.exe' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 11.10.0.3 / 11.10.1\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
exit(0, 'The file version of \''+path+'\\lmgrd.exe\' is '+version+' and thus is not affected.');

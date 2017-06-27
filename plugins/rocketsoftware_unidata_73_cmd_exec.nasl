#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(59607);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_bugtraq_id(53974);
  script_osvdb_id(82942);
  script_xref(name:"TRA", value:"TRA-2012-05");

  script_name(english:"Rocket Software UniData < 7.3 unidata72 Remote Command Execution (credentialed check)");
  script_summary(english:"Checks version of UniData");

  script_set_attribute(attribute:"synopsis", value:
"An RPC service on the remote Windows host allows commands to be run
without authentication.");

  script_set_attribute(attribute:"description", value:
"The version of UniData installed on the remote Windows host is
potentially affected by a code execution vulnerability.  The UniData
RPC service fails to enforce authentication on the unidata72
interface. 

An unauthenticated, remote attacker can exploit this vulnerability to
execute arbitrary code on the remote host with SYSTEM level
privileges.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2012-05");
  script_set_attribute(attribute:"see_also", value:"https://www.usploit.com/index.php?advisories/view/UPS-2012-0012");
  script_set_attribute(attribute:"solution", value:"Upgrade to UniData 7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("rocketsoftware_unidata_detect.nasl");
  script_require_keys("SMB/RocketSoftware/UniData/installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/RocketSoftware/UniData/installed');
installs = get_kb_list('SMB/RocketSoftware/UniData/*/path');
if (isnull(installs)) exit(1, 'The SMB/RocketSoftware/UniData/*/path KB list is missing.');

vuln = 0;
report = '';
foreach item (keys(installs))
{
  ver = item - 'SMB/RocketSoftware/UniData/';
  ver = ver - '/path';
  ver = split(ver, sep:'.', keep:FALSE);

  version = ver[0] + '.' + ver[1] + '.' + ver[2];
  if (ver_compare(ver:version, fix:'7.3', strict:FALSE) == -1)
  {
    vuln++;
   
    path = installs[item];
    if (isnull(path)) path = 'n/a';

    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.3\n';
  }
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    if (vuln > 1) s = 's of Rocket Software UniData were found ';
    else s = ' of Rocket Software UniData was found ';

    report = 
      '\n  The following vulnerable install' + s + 'on the' +
      '\n  remote host :' +
      '\n' + 
      report + '\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(port:get_kb_item('SMB/transport'));
  exit(0);
}
else exit(0, 'No vulnerable installs of Rocket Software were detected on the remote host.');

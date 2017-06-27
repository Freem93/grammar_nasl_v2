#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62076);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2012-2753");
  script_bugtraq_id(53925);
  script_osvdb_id(82840);

  script_name(english:"Check Point Remote Access Client Insecure Library Loading");
  script_summary(english:"Checks version of Remote Access Client");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a VPN client installed that is affected by
an insecure library loading vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Check Point Remote Access Client installed on the remote
Windows host is earlier than E75.10 and is, therefore, reportedly
affected by an insecure library loading vulnerability.  If an attacker
can trick a user on the affected system into opening a specially crafted
file, they may be able to leverage this issue to execute arbitrary code
subject to the user's privileges.");
   # https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk76480
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5b32f63");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Jun/68");
  script_set_attribute(attribute:"solution", value:"Upgrade to Check Point Remote Access Client E75.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:checkpoint:remote_access_clients");
  script_end_attributes();
  
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("checkpoint_endpoint_rac_installed.nasl");
  script_require_keys("SMB/Check Point Remote Access Client/Installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit('SMB/Check Point Remote Access Client/Installed');

installs = get_kb_list('SMB/Check Point Remote Access Client/*/Path');
if (isnull(installs)) exit(1, 'The \'SMB/Check Point Remote Access Client/*/Path\' KB list is missing.');

info = '';
info2 = '';
vuln = 0;
foreach install (keys(installs))
{
  path = installs[install];
  version = install - 'SMB/Check Point Remote Access Client/';
  version = version - '/Path';
  verui = get_kb_item('SMB/Check Point Remote Access Client/'+version+'/VerUI');
  if (isnull(verui)) verui = version;

  fix = '83.5.168.25';
  if (ver_compare(ver:version, fix:fix) == -1)
  {
    vuln++;
    info += 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + verui +
      '\n  Fixed version     : E75.20\n';
  }
  else info2 += ' and ' + verui;
}

if (info)
{
  if (report_verbosity > 0) security_warning(port:get_kb_item('SMB/transport'), extra:info);
  else security_warning(get_kb_item('SMB/transport'));
  exit(0);
}

if (info2)
{
  info2 -= ' and ';
  if (' and ' >< info2) be = 'are';
  else be = 'is';

  exit(0, 'The host is not affected since Check Point Remote Access Client ' + info2 + ' ' + be + ' installed.');
}
else exit(1, 'Unexpected error - \'info2\' is empty.');

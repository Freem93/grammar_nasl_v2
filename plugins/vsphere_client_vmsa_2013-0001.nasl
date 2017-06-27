#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64559);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/04/20 04:29:52 $");

  script_cve_id("CVE-2013-1405");
  script_bugtraq_id(57666);
  script_osvdb_id(89755);
  script_xref(name:"VMSA", value:"2013-0001");

  script_name(english:"VMware vSphere Client Memory Corruption (VMSA-2013-0001)");
  script_summary(english:"Checks version of vSphere Client");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization client application installed that
is affected by a memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of vSphere Client installed on the remote Windows host is
potentially affected by a memory corruption issue in the authentication
mechanism.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0001.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to vSphere Client 4.0 Update 4b / 4.1 Update 3a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vsphere_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("vsphere_client_installed.nasl");
  script_require_keys("SMB/VMware vSphere Client/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

installs = get_kb_list_or_exit("SMB/VMware vSphere Client/*/Path");

info = '';
info2 = '';
vuln = 0;
foreach version (keys(installs))
{
  path = installs[version];
  version = version - 'SMB/VMware vSphere Client/' - '/Path';
  matches = eregmatch(pattern:'^([0-9\\.]+) build ([0-9]+)$', string:version);
  if (matches)
  {
    ver = matches[1];
    build = matches[2];
  }

  if (ver =~ '^4\\.1\\.0$' && int(build) < 925676)
  {
    vuln++;
    info += 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.1.0 build 925676\n';
  }
  else if (ver =~ '^4\\.0\\.0$' && int(build) < 934018)
  {
    vuln++;
    info += 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.0.0 build 934018\n';
  }
  else info2 += ' and ' + version;
}

if (vuln)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0) security_hole(port:port, extra:info);
  else security_hole(port);
  exit(0);
}

if (info2)
{
  info2 -= ' and ';
  if (' and ' >< info2) be = 'are';
  else be = 'is';

  exit(0, 'The host is not affected since VMware vSphere Client'+info2+' '+be+' installed.');
}
else exit(1, 'Unexpected error - \'info2\' is empty.');

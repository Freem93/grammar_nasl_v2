#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62310);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/09/27 11:14:26 $");

  script_cve_id("CVE-2012-4603");
  script_bugtraq_id(55518);
  script_osvdb_id(85425);
  script_xref(name:"IAVB", value:"2012-B-0094");

  script_name(english:"Citrix Receiver / Online Plug-in Remote Code Execution (CTX134681)");
  script_summary(english:"Checks version of Receiver and Online Plug-in");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a remote access application installed that
is affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"Citrix Receiver prior to 3.3 or Citrix Online Plug-in prior to 12.3 is
installed on the remote Windows host.  As such, the install is
potentially affected by an unspecified code execution vulnerability.  By
exploiting this flaw, a remote, unauthenticated attacker could execute
arbitrary code on the client device in the context of the currently
logged in user.");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX134681");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Receiver 3.3 or later, or Citrix Online Plug-in 12.3
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:receiver");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:online_plug-in");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:citrix_ica_client");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  
  script_dependencies("citrix_receiver_installed.nasl", "citrix_onlineplugin_installed.nasl");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

ver1 = get_kb_item('SMB/Citrix Receiver/Version');
ver2 = get_kb_item('SMB/Citrix Online Plug-in/Version');

if (isnull(ver1) && isnull(ver2))
  exit(0, 'The \'SMB/Citrix Receiver/Version\' and \'SMB/Citrix Online Plug-in/Version\' KB items are missing.');

report = '';
info2 = '';
if (ver1)
{
  if (ver_compare(ver:ver1, fix:'3.3.0.17207') == -1)
  {
    path1 = get_kb_item('SMB/Citrix Receiver/Path');
    if (isnull(path1)) path1 = 'n/a';
    report += 
      '\n  Product           : Citrix Receiver' +
      '\n  Path              : ' + path1 +
      '\n  Installed version : ' + ver1 + 
      '\n  Fixed version     : 3.3.0.17207\n';
  }
  else info2 += ' and Citrix Receiver ' + ver1; 
}
if (ver2)
{
  if (ver_compare(ver:ver2, fix:'12.3.0.8') == -1)
  {
    path2 = get_kb_item('SMB/Citrix Online Plug-in/Path');
    if (isnull(path2)) path2 = 'n/a';
    report +=
      '\n  Product           : Citrix Online Plug-in' +
      '\n  Path              : ' + path2 +
      '\n  Installed version : ' + ver2 +
      '\n  Fixed version     : 12.3.0.8\n';
  }
  else info2 += ' and Citrix Online Plug-in ' + ver2;
}

if (report)
{
  if (report_verbosity > 0) security_hole(port:get_kb_item('SMB/transport'), extra:report);
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}

if (info2)
{
  info2 -= ' and ';
  if (' and ' >< info2) be = 'are';
  else be = 'is';

  exit(0, 'The host is not affected since ' + info2 + ' ' + be + ' installed.');
}
else exit(1, 'Unexpected error - \'info2\' is empty.');

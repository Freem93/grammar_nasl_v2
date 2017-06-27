#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62925);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id("CVE-2012-4953");
  script_bugtraq_id(56399);
  script_osvdb_id(87403);
  script_xref(name:"CERT", value:"985625");
  script_xref(name:"IAVA", value:"2012-A-0192");

  script_name(english:"Symantec Legacy Decomposer Code Execution (SYM12-017)");
  script_summary(english:"Checks version of Symantec Endpoint Protection / Scan Engine");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an antivirus application that is affected
by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection or Symantec Scan Engine
installed on the remote Windows host is potentially affected by a code
execution vulnerability. The legacy decomposer engine fails to
properly handle bounds-checking when parsing files from some versions
of CAB archives.");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20121107_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4edb61b4");
  # http://clientui-kb.symantec.com/kb//index?page=content&id=TECH200168&actp=RSS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9cc0e1b");
  script_set_attribute(attribute:"solution", value:
"For Symantec AntiVirus 10.x, upgrade to Symantec Enpoint Protection
12.1 or later.

For Symantec Enpoint Protection 11.x or 12.0, either run Live Update
to upgrade the decomposer engine to version 1.2.8.4 or upgrade to
Symantec Endpoint Proection 12.1 or later.

For Symantec Scan Engine, upgrade to Symantec Scan Engine 5.2.8 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:scan_engine");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("savce_installed.nasl", "symantec_scan_engine_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

sep_version = get_kb_item("Antivirus/SAVCE/version");
sse_version = get_kb_item("Symantec/Symantec Scan Engine/Version");
if (isnull(sep_version) && isnull(sse_version)) exit(0, 'The \'Antivirus/SAVCE/version\' and \'Symantec/Symantec Scan Engine/Version\' KB items are missing.');

info = '';
info2 = '';
# First check Symantec Endpoint
if (sep_version)
{
  ver = split(sep_version, sep:'.');
  for (i=0; i < max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (ver[0] == 10)
  {
    prod = 'Symantec AntiVirus';
    info =
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + sep_version +
      '\n  Fixed version     : 12.1\n';
  }
  else if (
    ver[0] == 11 ||
    (ver[0] == 12 && ver[1] < 1)
  )
  {
    # Check the Decomposer Engine version
    arch = get_kb_item('SMB/ARCH');
    if (!isnull(arch))
    {
      if (arch == 'x64')
      {
        path = hotfix_get_programfilesdirx86();
        if (path) path += "\Common Files\Symantec Shared";
      }
      else
      {
        path = hotfix_get_commonfilesdir();
        if (path) path += "\Symantec Shared";
      }
    }
    if (!path)
    {
      NetUseDel();
      audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
    }
    dll = path + "\dec_abi.dll";
    ver = hotfix_get_fversion(path:dll);
    # If the Architecture is 64-bit and the file wasn't in the x86 Common Files dir
    # Check the Common files dir
    if (ver['error'] == HCF_NOENT && arch == 'x64')
    {
      path = hotfix_get_commonfilesdir();
      if (path) path += "\Symantec Shared";
      if (!path)
      {
        NetUseDel();
        audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
      }
      dll = path + "\dec_abi.dll";
      ver = hotfix_get_fversion(path:dll);
    }
    if (ver['error'] == HCF_OK)
    {
      version = join(ver['value'], sep:'.');
      if (ver_compare(ver:version, fix:'1.2.8.4', strict:FALSE) == -1)
      {
        info =
          '\n  Product : Symantec Endpoint Protection' +
          '\n  Installed decomposer engine version : ' + version +
          '\n  Fixed decomposer engine version     : 1.2.8.4\n';
      }
      else info2 += 'Symantec Endpoint Protection decomposer engine version ' + version;
    }
  }
  else info2 += 'Symantec Endpoint Protection version ' + version;
}

# Next check Symantec Scan Engine
if (sse_version)
{
  if (ver_compare(ver:sse_version, fix:'5.2.8', strict:FALSE) == -1)
  {
    path = get_kb_item('Symantec/Symantec Scan Engine/Path');
    if (isnull(path)) path = 'n/a';
    info +=
      '\n  Product           : Symantec Scan Engine' +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + sse_version +
      '\n  Fixed version     : 5.2.8\n';
  }
  else
  {
    if (info2)
      info2 += ' and Symantec Scan Engine version ' + sse_version;
  }
}

if (info)
{
  if (report_verbosity > 0) security_hole(port:get_kb_item('SMB/transport'), extra:info);
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}
else
{
  if (info2)
  {
    if ('and' >< info2)
      be = 'are';
    else be = 'is';

    exit(0, 'The host is not affected since ' + info2 + ' ' + be + ' installed.');
  }
  else exit(1, 'Unexpected error - \'info2\' is empty.');
}

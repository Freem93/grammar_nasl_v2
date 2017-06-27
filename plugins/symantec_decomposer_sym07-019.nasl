#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67002);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:22:01 $");

  script_cve_id("CVE-2007-0447", "CVE-2007-3699");
  script_bugtraq_id(24282);
  script_osvdb_id(36118, 36119);

  script_name(english:"Symantec Antivirus Scan Engine RAR and CAB Parsing Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Symantec Antivirus Scan Engine");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a heap overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
  "The remote host is running a version of the Symantec Mail Security for
Exchange / Domino that is affected by multiple vulnerabilities :

  - A heap overflow vulnerability exists that can be
    triggered when the scanning engine processes a specially
    crafted CAB file, possibly leading to arbitrary code
    execution. (CVE-2007-0447)

  - It is is possible to trigger a denial of service
    condition when the scanning engine processes a RAR file
    with a specially crafted header. (CVE-2007-3699)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-040/");
  # http://www.symantec.com/business/support/index?page=content&id=TECH102208
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?02420ead");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2007.07.11f.html");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate updates per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:antivirus_scan_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("savce_installed.nasl", "symantec_scan_engine_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

sep_version = get_kb_item("Antivirus/SAVCE/version");
sse_version = get_kb_item("Symantec/Symantec Scan Engine/Version");
if (isnull(sep_version) && isnull(sse_version)) exit(0, 'The \'Antivirus/SAVCE/version\' and \'Symantec/Symantec Scan Engine/Version\' KB items are missing.');

info = '';
info2 = '';

# First check Symantec Endpoint
if (sep_version)
{
  ver = split(sep_version, sep:'.', keep:FALSE);
  for (i=0; i < max_index(ver); i++)
  {
    item = eregmatch(pattern:"^[0]*([1-9][0-9]*)$", string:ver[i]);
    if (isnull(item) || isnull(item[1]))
      exit(1, "Error parsing version string.");
    ver[i] = int(item[1]);
  }

  if ((ver[0] == 10 && ver[1] < 1) ||
      (ver[0] == 10 && ver[1] == 1 && ver[2] < 5) ||
      (ver[0] == 10 && ver[1] == 1 && ver[2] == 5 && ver[3] < 5010))
  {
    prod = 'Symantec AntiVirus';
    info =
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + sep_version +
      '\n  Fixed version     : 10.1.5.5010\n';
  }
  else if (ver[0] == 8 ||
          (ver[0] == 9 && ver[1] == 0 && ver[2] < 6) ||
          (ver[0] == 9 && ver[1] == 0 && ver[2] == 6 && ver[3] < 1100))
  {
    prod = 'Symantec AntiVirus';
    info =
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + sep_version +
      '\n  Fixed version     : 9.0.6.1100\n';
  }
  else info2 += 'Symantec Endpoint Protection version ' + sep_version;
}

# Next check Symantec Scan Engine
if (sse_version)
{
  fix = '';

  if (sse_version =~ "^4\.3\." &&
      ver_compare(ver:sse_version, fix:'4.3.12', strict:FALSE) <= 0)
    fix = "4.3.17";
  else if (sse_version =~ "^4\.0\." ||
          (sse_version =~ "^4\.1\." &&
           ver_compare(ver:sse_version, fix:'4.1.8', strict:FALSE) <= 0))
    fix = "4.3.18.43";
  else if (sse_version =~ "^5\.0\." &&
           ver_compare(ver:sse_version, fix:'5.0.1', strict:FALSE) <= 0)
    fix = "5.1.4.24";

  if (fix != '')
  {
    path = get_kb_item('Symantec/Symantec Scan Engine/Path');
    if (isnull(path)) path = 'n/a';
    info +=
      '\n  Product           : Symantec Scan Engine' +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + sse_version +
      '\n  Fixed version     : ' + fix + '\n';
  }
  else
  {
    if (info2)
      info2 += ' and Symantec Scan Engine version ' + sse_version;
  }
}

if (info)
{
  port = kb_smb_transport();
  if (report_verbosity > 0) security_hole(port:port, extra:info);
  else security_hole(port);
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

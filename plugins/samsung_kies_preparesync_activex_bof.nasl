#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(63686);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/05/23 15:38:27 $");

  script_cve_id("CVE-2012-6429");
  script_bugtraq_id(57249);
  script_osvdb_id(89118);

  script_name(english:"Samsung Kies SyncService ActiveX PrepareSync() Buffer Overflow");
  script_summary(english:"Checks version of ActiveX Control");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by a buffer
overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the version of Samsung Kies SyncService ActiveX installed
on the remote host, the 'PrepareSync()' method is affected by a buffer
overflow vulnerability.

A remote attacker could use this vulnerability to cause a denial of
service or potentially execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www.htbridge.com/advisory/HTB23136");
  script_set_attribute(attribute:"solution", value:"Upgrade to Samsung Kies 2.5.1.12123_2_7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samsung:kies");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

clsid = '{EA8A3985-F9DF-4652-A255-E4E7772AFCA8}';

if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, "activex_get_filename() returned NULL.");
}
if (!file)
{
  activex_end();
  audit(AUDIT_ACTIVEX_NOT_FOUND, clsid);
}

# Get its version.
version = activex_get_fileversion(clsid:clsid);
if (!version) version = "unknown";

info = "";
if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
{
    info += '\n  Class identifier  : ' + clsid +
            '\n  Filename          : ' + file +
            '\n  Installed version : ' + version + '\n';
}
activex_end();

# Report findings.
if (info)
{
  if (report_paranoia > 1)
  {
    report = info +
      '\n' +
      'Note, though, that Nessus did not check whether the kill bit was\n' +
      'set for the control\'s CLSID because of the Report Paranoia setting\n' +
      'in effect when this scan was run.\n';
  }
  else
  {
    report = info +
      '\n' +
      'Additionally, the kill bit is not set for this ActiveX control,\n' +
      'making it accessible via Internet Explorer.\n';
  }

  if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());
  exit(0);
}
else
{
  if (version == "unknown") exit(0, "An unknown version of the control is installed, but its kill bit is set.");
  audit(AUDIT_ACTIVEX, version);
}

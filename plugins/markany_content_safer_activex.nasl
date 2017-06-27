#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(63268);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/05/23 15:38:26 $");

  script_cve_id("CVE-2012-2990");
  script_bugtraq_id(55192);
  script_osvdb_id(84938);
  script_xref(name:"CERT", value:"663809");

  script_name(english:"MarkAny Content SAFER ActiveX Arbitrary Download and Execution");
  script_summary(english:"Checks version of ActiveX Control");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by an arbitrary
file write vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has the MarkAny Content SAFER ActiveX control
installed, which is distributed with Samsung KIES.  It is affected by an
arbitrary file write vulnerability that is triggered during the parsing
of a method call.  This may allow attackers to overwrite or download
arbitrary files."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.markany.com/en/?p=2307");
  # https://www.krcert.or.kr/kor/data/secNoticeView.jsp?p_bulletin_writing_sequence=931
  script_set_attribute(attribute:"solution", value:"Upgrade to MarkAny Content SAFER version 1.4.2012.508 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samsung:kies");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:markany:content_safer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

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

clsid = '{99806ADD-C5EF-4632-A3D0-3E778B051F94}';

if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

info = '';

fix = '1.4.2012.508';

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
if (!version)
{
  activex_end();
  audit(AUDIT_VER_FAIL, file);
}

if (ver_compare(ver:version, fix:fix) == -1)
{
  if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
      info += '\n  Class identifier  : ' + clsid +
              '\n  Filename          : ' + file +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : ' + fix + '\n';
   }
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
  if (ver_compare(ver:version, fix:fix) >= 0) audit(AUDIT_INST_VER_NOT_VULN, file, version);
  else audit(AUDIT_ACTIVEX, version);
}

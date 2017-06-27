#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45593);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/19 01:42:50 $");

  script_cve_id("CVE-2010-1033");
  script_bugtraq_id(39578);
  script_osvdb_id(63931);
  script_xref(name:"EDB-ID", value:"12302");

  script_name(english:"HP Operations Manager SourceView ActiveX LoadFile / SaveFile Stack Overflows");
  script_summary(english:"Checks version of the SourceView control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is susceptible to
buffer overflow attacks.");
  script_set_attribute(attribute:"description", value:
"The SourceView ActiveX control, a component of HP Operations Manager,
installed on the remote Windows host reportedly is affected by buffer
overflows that can be triggered by passing specially crafted Unicode
strings to the 'LoadFile' or 'SaveFile' methods.

If an attacker can trick a user on the affected host into viewing a
specially crafted HTML document, he can leverage this issue to execute
arbitrary code on the affected system subject to the user's
privileges.");
  # https://www.corelan.be/index.php/forum/security-advisories-archive-2010/corelan-10-027-hp-operations-manager-remote-bof/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4cc251dd");
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2010/Apr/250"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02078800
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?333a47bf"
  );
  script_set_attribute(attribute:"solution", value:"Apply the appropriate patch referenced in HP's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:operations_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");
include("audit.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");


# Check first for the ActiveX control.
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

fixed_versions = make_array();
# - v8.10 and v8.16
fixed_versions['{366C9C52-C402-416B-862D-1464F629CA59}'] = '4.0.1.2';
# - v7.5
fixed_versions['{C1BA4C71-0F4F-11D1-8F93-EC6D05C10000}'] = '2.23.29';

all_files = make_array();
vuln_files = make_array();
infos = make_array();

foreach clsid (keys(fixed_versions))
{
  file = activex_get_filename(clsid:clsid);
  if (isnull(file))
  {
    activex_end();
    exit(1, "activex_get_filename() returned NULL.");
  }
  if (!file) continue;

  all_files[clsid] = file;

  # Check its version.
  version = activex_get_fileversion(clsid:clsid);
  fixed_version = fixed_versions[clsid];

  if (version && activex_check_fileversion(clsid:clsid, fix:fixed_version) == TRUE)
  {
    if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
    {
      vuln_files[clsid] = file;

      infos[clsid] =
        '\n  Class Identifier  : ' + clsid +
        '\n  Filename          : ' + file +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
    }
  }
}
activex_end();

if (max_index(keys(all_files)) == 0) exit(0, "The control is not installed.");
if (max_index(keys(vuln_files)) == 0)
{
  s = '';
  foreach clsid (sort(keys(all_files)))
    s = strcat(s, ' & ', all_files[clsid], ' (', clsid, ')');
  s = substr(s, 3);

  if (max_index(keys(all_files)) == 1) exit(0, "The control is installed as "+s+", but its kill bit is set.");
  else exit(0, "The controls are installed as "+s+", but their kill bits are set.");
}


# Identify only controls associated with an install of HP Operations Manager.
#
# nb: we don't have any info about whether other installs of the
#     control are affected so we're only flagging those from HP
#     Operations Manager.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

installs = 0;
report = '';
foreach clsid (sort(keys(vuln_files)))
{
  file = vuln_files[clsid];
  path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+$', replace:"\1", string:file);

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\ovcd.exe", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to "+share+" share.");
  }

  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    installs++;
    report = strcat(report, infos[clsid]);

    CloseFile(handle:fh);
    NetUseDel(close:FALSE);
  }
}
NetUseDel();


# Report findings.
if (report)
{
  if (report_paranoia > 1)
  {
    if (installs == 1) s = " was";
    else s = "s were";

    report = strcat(
      report,
      '\n',
      'Note, though, that Nessus did not check whether the kill bit', s, '\n',
      'set for the control\'s CLSID because of the Report Paranoia setting\n',
      'in effect when this scan was run.\n'
    );
  }
  else
  {
    if (installs == 1) s = "its kill bit is not set so it is";
    else s = "their kill bits are not set so they are";

    report = strcat(
      report,
      '\n',
      'Moreover, ', s, ' accessible via Internet\n',
      'Explorer.\n'
    );
  }

  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
  exit(0);
}
else
{
  s = '';
  foreach clsid (sort(keys(all_files)))
    s = strcat(s, ' & ', all_files[clsid], ' (', clsid, ')');
  s = substr(s, 3);

  if (max_index(keys(all_files)) == 1) exit(0, "The control is installed as "+s+", but it is not part of an HP Operations Manager install.");
  else exit(0, "The controls are installed as "+s+", but neither is part of an HP Operations Manager install.");
}

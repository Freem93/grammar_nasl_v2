#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57536);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/29 21:03:42 $");

  script_cve_id("CVE-2012-6501");
  script_bugtraq_id(51341);
  script_osvdb_id(78272);
  script_xref(name:"Secunia", value:"47122");

  script_name(english:"HP PKI ActiveX Control KillProcess Denial of Service");
  script_summary(english:"Checks control's version / kill bit");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control that is affected by a
denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of the HP PKI ActiveX control installed on the remote
Windows host is earlier than 1.2.0.1.  As such, it reportedly contains
an insecure method named 'KillProcess()' that could be used to
terminate arbitrary user processes."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to version 1.2.0.1 or later as that reportedly resolves the
vulnerability :

https://digitalbadge.external.hp.com/hp/HPPKI.cab"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:pki_activex_control");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");


# Determine if the control is installed.
clsids = make_list(
  '{AB01FF2E-A848-410C-B47B-CB467C476AD9}',
  '{857ABA85-8AB2-4C9E-8FAA-D2A963739859}'
);
fixed_version = "1.2.0.1";
installs = 0;

info = '';
foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (isnull(file))
  {
    debug_print('activex_get_filename() returned NULL.');
    continue;
  }
  if (!file)
  {
    debug_print("There is no ActiveX control using the class id '"+clsid+"' on the host.");
    continue;
  }
  installs++;

  # Get its version.
  version = activex_get_fileversion(clsid:clsid);

  # And check it.
  if (version && activex_check_fileversion(clsid:clsid, fix:fixed_version) == TRUE)
  {
    if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
    {
      info += 
        '\n  Class identifier  : ' + clsid +
        '\n  Filename          : ' + file +
        '\n  Installed version : ' + version + 
        '\n  Fixed version     : ' + fixed_version + '\n';
     } 
  }
}
activex_end();
if (!installs) exit(0, 'None of the affected controls were found on the remote host.');


# Report findings.
if (info)
{
  # At this point, we want to know how many *vulnerable* installs there are.
  installs = max_index(split(info)) / 5;

  if (report_paranoia > 1)
  {
    if (installs == 1)
      report = info +
        '\n' +
        '\nNote, though, that Nessus did not check whether the kill bit was set' +
        '\nfor the control\'s CLSID because of the Report Paranoia setting in' +
        '\neffect when this scan was run.\n';
    else
      report = info +
        '\n' +
        '\nNote, though, that Nessus did not check whether the kill bits were set' +
        '\nfor the controls\' CLSIDs because of the Report Paranoia setting in' +
        '\neffect when this scan was run.\n';
  }
  else
  {
    if (installs == 1)
      report = info +
        '\n' +
        '\nMoreover, its kill bit is not set so it is accessible via Internet' +
        '\nExplorer.\n';
    else
      report = info +
        '\n' +
        '\nMoreover, their kill bits are not set so they are accessible via' +
        '\nInternet Explorer.\n';
  }

  if (report_verbosity > 0) security_warning(port:kb_smb_transport(), extra:report);
  else security_warning(kb_smb_transport());
  exit(0);
}
else 
{
  if (installs == 1) exit(0, 'One of the controls is installed but its kill bit is set.');
  else exit(0, 'The controls are installed but their kill bits are set.');
}

#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(58597);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_cve_id("CVE-2012-4876");
  script_bugtraq_id(52760);
  script_osvdb_id(80661);
  script_xref(name:"EDB-ID", value:"18675");
  script_xref(name:"EDB-ID", value:"18709");

  script_name(english:"TRENDnet SecurView UltraMJCam ActiveX Control OpenFileDlg Method WideCharToMultiByte() Call Remote Overflow");
  script_summary(english:"Checks if the kill bit is set");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has the TRENDnet SecurView UltraMJCam ActiveX control
installed. A stack-based buffer overflow can be triggered by providing
an overlong argument to the 'OpenFileDlg()' method.  This is because
the method does not verify the size of the argument before calling
'WideCharToMultiByte()'.

By tricking a user into opening a specially crafted web page, a
remote, unauthenticated attacker could execute arbitrary code on the
remote host subject to the user's privileges."
  );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/9sg_trendnet_adv.htm");
  script_set_attribute(
    attribute:"solution",
    value:"Remove or disable the control as fixes are not available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'TRENDnet SecurView Internet Camera UltraMJCam OpenFileDlg Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:trendnet:securview_wireless_internet_camera_activex_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');
include('smb_activex_func.inc');
include('misc_func.inc');
include('global_settings.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (activex_init() != ACX_OK) exit(1, 'activex_init() failed.');

clsid = '{707ABFC2-1D27-4a10-A6E4-6BE6BDF9FB11}';

# Make sure the control is installed
file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, "activex_get_filename() returned NULL.");
}
if (!file)
{
  activex_end();
  exit(0, "The control is not installed since the class id '"+clsid+"' is not defined on the remote host.");
}

# Get its version
version = activex_get_fileversion(clsid:clsid);
if (!version) version = 'unknown';

info = "";
if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
{
  info +=
    '\n  Class identifier  : ' + clsid +
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
      "set for the control's CLSID because of the Report Paranoia setting" + '\n' +
      'in effect when this scan was run.\n';
  }
  else
  {
    report = info +
      '\n' +
      'Moreover, its kill bit is not set so it is accessible via Internet\n' +
      'Explorer.\n';
  }

  if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());

  exit(0);
}
else exit(0, "The control is installed, but its kill bit is set.");

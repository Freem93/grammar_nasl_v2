#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60022);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/04/17 18:47:27 $");

  script_bugtraq_id(49192);
  script_osvdb_id(74611);

  script_name(english:"StudioLine Photo Basic NMSDVDXU.dll ActiveX EnableLog() Arbitrary File Overwrite");
  script_summary(english:"Checks version of Photo Basic");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by an
arbitrary file overwrite vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of StudioLine Photo Basic less than or
equal to 3.70.34.0 installed.  Such versions are affected by an
arbitrary file overwrite vulnerability in the EnableLog() method on
the NMSDVDXU.dll ActiveX control.

By tricking a victim into opening a specially crafted web page, an
attacker could overwrite arbitrary files on the remote host subject to
the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.htbridge.com/advisory/HTB23024");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to a version of StudioLine Photo Basic greater than 3.70.34.0
or remove / disable the vulnerable ActiveX control."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:studioline:photobasic");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("studioline_photobasic_installed.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/StudioLine_PhotoBasic/Installed", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = 'StudioLine Photo Basic';
kb_base = "SMB/StudioLine_PhotoBasic/";

get_kb_item_or_exit(kb_base + 'Installed');

installs = get_kb_list(kb_base + 'Installs/*');
if (isnull(installs)) exit(1, 'The \'' + kb_base + 'Installs\' KB list is missing.');

info = '';
info2 = '';

if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

# Determine if the control is installed.
clsid = '{C2FBBB5F-6FF7-4F6B-93A3-7EDB509AA938}';

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
activex_version = activex_get_fileversion(clsid:clsid);
if (!activex_version)
{
  activex_end();
  audit(AUDIT_VER_FAIL, file);
}

foreach install (keys(installs))
{
  path = installs[install];
  version = install - (kb_base + 'Installs/');

  if (ver_compare(ver:version, fix:'3.70.34.0') <= 0 &&
      (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0))
  {
    if(report_paranoia > 1)
    {
        info =
        '\n  StudioLine path    : ' + path +
        '\n  StudioLine version : ' + version +
        '\n  ActiveX  CLSID     : ' + clsid +
        '\n  ActiveX  path      : ' + file +
        '\n' +
        '\nNote, though, that Nessus did not check whether the kill bit was' +
        '\nset for the control\'s CLSID because of the Report Paranoia setting' +
        '\nin effect when this scan was run.\n';
    }
    else
    {
         info =
        '\n  StudioLine path    : ' + path +
        '\n  StudioLine version : ' + version +
        '\n  ActiveX  CLSID     : ' + clsid +
        '\n  ActiveX  path      : ' + file +
        '\n' +
        '\nMoreover, its kill bit is not set so it is accessible via Internet' +
        '\nExplorer.\n';
    }
    # we don't need to check other installs
    break;
  }
  else info2 += ' and ' + version;
}

activex_end();

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

  exit(0, 'The host is not affected since ' + appname + ' ' + info2 + ' ' + be + ' installed.');
}
else exit(1, 'Unexpected error - \'info2\' is empty.');

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33256);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_cve_id("CVE-2008-2641");
  script_bugtraq_id(29908);
  script_osvdb_id(46548);
  script_xref(name:"Secunia", value:"30832");

  script_name(english:"Adobe Reader < 7.1.0 / 8.1.2 SU1 Unspecified JavaScript Method Handling Arbitrary Code Execution");
  script_summary(english:"Checks version of Adobe Reader / Security Updates");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that allows remote
code execution.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Windows host
contains a flaw in the function Collab.collectEmailInfo() that could
allow a remote attacker to crash the application and/or to take
control of the affected system.

To exploit this flaw, an attacker would need to trick a user on the
affected system into opening a specially crafted PDF file.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb08-15.html");
  # http://helpx.adobe.com/acrobat/release-note/release-notes-reader-acrobat-8.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8de89698" );
  script_set_attribute(attribute:"solution", value:
"- If running 7.x, upgrade to version 7.1.0 or later.

- If running 8.x, upgrade to 8.1.2, if necessary, and then
    apply
    Adobe's Security Update 1 for 8.1.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");
  script_require_ports(139,445);
  exit(0);
}

#

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");

port = kb_smb_transport();
info = NULL;
vers = get_kb_list('SMB/Acroread/Version');
if (isnull(vers)) exit(0, 'The "SMB/Acroread/Version" KB item is missing.');

foreach ver (vers)
{
  path = get_kb_item('SMB/Acroread/'+ver+'/Path');
  if (isnull(path)) exit(1, 'The "SMB/Acroread/'+ver+'/Path" KB item is missing.');

  verui = get_kb_item('SMB/Acroread/'+ver+'/Version_UI');
  if (isnull(verui)) exit(1, 'The "SMB/Acroread/'+ver+'/Version_UI" KB item is missing.');

  # Regex stolen from adobe_reader_812.nasl
  if (ver && ver =~ "^([0-6]\.|7\.0|8\.(0\.|1\.[01][^0-9.]?))" )
    info += '  - ' + verui + ', under ' + path + '\n';
  else if (ver && ver =~ "^8\.1\.2($|[^0-9])" )
  {
    # Check HKLM\SOFTWARE\Adobe\Acrobat Reader\8.0\Installer\VersionSU

    # Connect to the appropriate share.
    name    =  kb_smb_name();
    #if (!get_port_state(port)) exit(0);
    login   =  kb_smb_login();
    pass    =  kb_smb_password();
    domain  =  kb_smb_domain();

    #soc = open_sock_tcp(port);
    #if (!soc) exit(0);

    #session_init(socket:soc, hostname:name);
    if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
    if (rc != 1)
    {
      NetUseDel();
      exit(0);
    }

    hklm_handle = RegConnectRegistry (hkey:HKEY_LOCAL_MACHINE);

    if (!isnull(hklm_handle))
    {
      handle = RegOpenKey(handle:hklm_handle,
      key:"SOFTWARE\Adobe\Acrobat Reader\8.0\Installer",
      mode:MAXIMUM_ALLOWED);

      if (!isnull(handle))
      {
        value = RegQueryValue(handle:handle, item:"VersionSU");

        # There is no value if there are no security updates
        # There is the assumption that security updates are cumulative
        if (isnull(value))
          info += '  - ' + verui + ', under ' + path + '\n';

        RegCloseKey(handle:handle);
      }

      RegCloseKey(handle:hklm_handle);
    }

    # Clean up
    NetUseDel ();
  }
}

if (isnull(info)) exit(0, 'The host is not affected.');

if (report_verbosity > 0)
{
  if (max_index(split(info)) > 1) s = "s of Adobe Reader are";
  else s = " of Adobe Reader is";

  report =
    '\nThe following vulnerable instance'+s+' installed on the'+
    '\nremote host :\n\n'+
    info;
  security_hole(port:get_kb_item("SMB/transport"), extra:report);
}
else security_hole(port);

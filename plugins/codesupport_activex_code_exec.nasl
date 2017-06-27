#
#  (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20220);
  script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_cve_id("CVE-2005-3650");
  script_bugtraq_id(15430);
  script_osvdb_id(20887);

  script_name(english:"First4Internet XCP Uninstallation CodeSupport.ocx ActiveX Control Arbitrary Code Execution");
  script_summary(english:"Checks for remote code execution vulnerability in CodeSupport ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is prone to remote
code execution.");
 script_set_attribute(attribute:"description", value:
"The remote host contains an ActiveX control from First4Internet called
CodeSupport. This control was likely installed by requesting an
uninstaller for Sony's XCP digital rights management software.

CodeSupport is marked as safe for scripting and makes several methods
available for any web page to use. Should a user visit a maliciously
crafted website, this would allow that website to execute arbitrary
code on the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://hack.fi/~muzzy/sony-drm/");
 script_set_attribute(attribute:"see_also", value:"http://www.freedom-to-tinker.com/?p=927" );
 script_set_attribute(attribute:"solution", value:
"On the affected host, locate the file 'codesupport.ocx', run the
following DOS commands, and reboot.

 regsvr32 /u '%windir%\downloaded program files\codesupport.ocx' cmd
/k del '%windir%\downloaded program files\codesupport.*'

assuming it's located in '%windir%\downloaded program files'.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/16");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  exit(1);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(1);
}


# Determine if the control is installed.
key = "SOFTWARE\Classes\CLSID\{4EA7C4C5-C5C0-4F5C-A008-8293505F71CC}";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) name = value[1];
  else name = NULL;

  RegCloseKey(handle:key_h);
}
else name = NULL;


# If it is...
if (name && "CodeSupport Control" >< name) {
  # Determine where it's installed.
  key = "SOFTWARE\Classes\CLSID\{4EA7C4C5-C5C0-4F5C-A008-8293505F71CC}\InprocServer32";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) {
      file = value[1];
    }
    RegCloseKey(handle:key_h);
  }

  # And its version.
  #
  # nb: no word on whether only certain versions of the control are
  #     affected so treat them all as bad.
  key = "SOFTWARE\Classes\CLSID\{4EA7C4C5-C5C0-4F5C-A008-8293505F71CC}\Version";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) {
      ver = value[1];
    }
    RegCloseKey(handle:key_h);
  }

  # Generate the report.
  if (file && ver && report_verbosity > 0) {
    report = string(
      "Version ", ver, " of the control is installed as \n",
      "\n",
      "  ", file, "\n"
    );
  }
  else report = desc;

  security_hole(port:port, extra:report);
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();

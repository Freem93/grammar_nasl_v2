#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20737);
  script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2015/01/12 17:12:50 $");

  script_cve_id("CVE-2006-0316");
  script_bugtraq_id(16262);
  script_osvdb_id(22486);
  script_xref(name:"CERT", value:"715730");

  script_name(english:"AOL You've Got Pictures ActiveX Control (YGPPicFinder.DLL) Overflow");
  script_summary(english:"Checks for overflow vulnerability in AOL You've Got Pictures ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host contains an ActiveX control from AOL called YPG
Picture Finder Tool. It was distributed along with various versions of
AOL's client software and from the You've Got Pictures website prior
to 2004. The 'YGPPicFinder.DLL' component of this control fails to
limit the amount of user-supplied data copied to a finite buffer. This
can be exploited using a specially crafted web page, for example to
overflow the buffer, crash the application using the control
(typically Internet Explorer), and possibly execute arbitrary code
subject to the user's privileges.");
 script_set_attribute(attribute:"see_also", value:"http://download.newaol.com/security/YGPClean.exe");
 script_set_attribute(attribute:"solution", value:"Download and run AOL's removal tool.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/18");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:aol:aol_client_software");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

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
  exit(0);
}


name = NULL;
# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(0);
}


# Determine if the control is installed.
clid = "B33CCD56-0909-42C9-8A88-8976F66B8BF2";
key = "SOFTWARE\Classes\CLSID\{" + clid +  "}";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value))
    name = value[1];
  else
    name = NULL;

  RegCloseKey(handle:key_h);
}
else name = NULL;


# If it is...
if (name) {
  # Determine where it's installed.
  key = "SOFTWARE\Classes\CLSID\{" + clid + "}\InprocServer32";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) {
      if (value[1] =~ "YGPPicFinder") file = value[1];
    }
    RegCloseKey(handle:key_h);
  }

  # Generate the report.
  if (file ) {
    report = string(
      "The YPG Picture Finder Tool ActiveX control is installed as \n",
      "\n",
      "  ") + file + '\n';
      security_hole(port:port, extra: report);
  }

}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();

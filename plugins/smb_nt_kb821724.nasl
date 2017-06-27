#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18491);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/09 20:54:59 $");

  script_bugtraq_id(13955);
  script_osvdb_id(17342);

  script_name(english:"MS KB821724: ISA Server 2000 May Send Basic Credentials Over an External HTTP Connection");
  script_summary(english:"Checks for a registry key");

  script_set_attribute(attribute:'synopsis', value:"The remote service is vulnerable to information disclosure.");
  script_set_attribute(attribute:'description', value:
"The remote ISA server is configured in such a way that it may send
Basic authentication credentials over an insecure connection.");
  script_set_attribute(attribute:'solution', value:
"Upgrade to the latest version of ISA or apply the patch referenced in
KB821724.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:'see_also', value:"http://support.microsoft.com/?id=821724");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:isa_server:2000");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/registry_full_access","SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("audit.inc");
include("smb_func.inc");

if (!get_kb_item("SMB/registry_full_access")) exit(1, "Registry not fully accessible.");

# Is ISA installed ?
fpc = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!fpc) exit(0, "ISA not installed.");


login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
 {
  NetUseDel();
  audit(AUDIT_REG_FAIL);
 }

# First make sure this looks like ISA 2000
gte_isa2004 = FALSE;
key = "SOFTWARE\Microsoft\Fpc";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    isaver = RegEnumKey(handle:key_h, index:i);
    match = eregmatch(string:isaver, pattern:'^([0-9])[0-9.]+$');
    if (match && int(match[1]) >= 4)
    {
      gte_isa2004 = TRUE;
      break;
    }
  }
  RegCloseKey(handle:key_h);
}

if (gte_isa2004)
{
  NetUseDel();
  exit(0, 'ISA version ' + isaver + ' is not affected.');
}

# Then check for the relevant config setting
key = "SYSTEM\CurrentControlSet\Services\W3Proxy\Parameters";
item = "DontAskBasicAuthOverNonSecureConnection";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
  value = RegQueryValue(handle:key_h, item:item);
  RegCloseKey (handle:key_h);
}
RegCloseKey (handle:hklm);
NetUseDel();

if ( isnull(value) || value[1] == 0 ) security_warning(get_kb_item("SMB/transport"));

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55568);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/04 17:57:39 $");

  script_cve_id("CVE-2007-4415");
  script_bugtraq_id(25332);
  script_osvdb_id(40872);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsj00785");
  script_xref(name:"IAVA", value:"2009-A-0106");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtn50645");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20070815-vpnclient");

  script_name(english:"Cisco VPN Client cvpnd.exe Privilege Escalation");
  script_summary(english:"Local version check");

  script_set_attribute(attribute:"synopsis", value:
"The VPN client installed on the remote Windows host has a privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco VPN client installed on the remote host has a privilege
escalation vulnerability. cvpnd.exe, which is executed by the Cisco
VPN Service, has insecure permissions. A local attacker could replace
this file with arbitrary code, which would later be executed by the
Cisco VPN Service, resulting in an elevation of privileges.

The following versions are vulnerable :

  - 32-bit versions prior to 5.0.01.0600
    - 64-bit version 5.0.7.0240
    - 64-bit version 5.0.7.0290");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?132892db");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco VPN Client 32-bit version 5.0.01.0600 / 64-bit
version 5.0.07.0440 or later. Cisco notes that the 32-bit MSI package
contains the fix for this vulnerability, while the IS package does
not.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:vpn_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_vpn_client_detect.nasl");
  script_require_keys("SMB/CiscoVPNClient/Version", "SMB/CiscoVPNClient/Path", "SMB/transport");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");
include("misc_func.inc");


ACCESS_ALLOWED_ACE_TYPE = 0;
path = get_kb_item_or_exit("SMB/CiscoVPNClient/Path");

name    =  kb_smb_name();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
path += "\cvpnd.exe";
share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(1, 'Can\'t connect to '+share+' share.');
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!fh)
{
  NetUseDel();
  exit(0, 'Can\'t access file \''+path+'\'.');
}

sd = GetSecurityInfo(handle:fh, level:DACL_SECURITY_INFORMATION);
CloseFile(handle:fh);
NetUseDel();

if (isnull(sd))
  exit(1, "Unable to access security descriptor for '"+path+"'.");

dacl = sd[3];
if (isnull(dacl))
  exit(1, "Unable to retrieve DACL for '"+path+"'.");

dacl = parse_pdacl(blob:dacl);
if (isnull(dacl)) exit(1, "Error parsing DACL for '"+path+"'.");

vulnerable = FALSE;

foreach ace (dacl)
{
  ace = parse_dacl(blob:ace);
  if (isnull(ace))
  {
    err_print("Error parsing ACE.");
    continue;
  }

  rights = ace[0];
  type = ace[3];
  sid = sid2string(sid:ace[1]);
  if (isnull(sid))
  {
    err_print(1, "Error parsing SID.");
    continue;
  }

  # Check if this is 1) an allow ACE 2) for interactive users 3) that allows write access
  if (
    type == ACCESS_ALLOWED_ACE_TYPE &&
    sid == '1-5-4' &&   # INTERACTIVE
    rights & FILE_GENERIC_WRITE == FILE_GENERIC_WRITE
  )
  {
    vulnerable = TRUE;
    break;
  }
}

if (vulnerable)
{
  if (report_verbosity > 0)
  {
    report = '\nThe INTERACTIVE group has write access for :\n\n'+path+'\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The host is not affected.");

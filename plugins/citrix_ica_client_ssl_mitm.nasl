#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42961);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/17 21:12:12 $");

  script_cve_id("CVE-2009-3936");
  script_bugtraq_id(37073);
  script_osvdb_id(59995);
  script_xref(name:"Secunia", value:"37319");

  script_name(english:"Citrix XenApp Online Plug-in / Receiver Crafted Certificate MitM Spoofing Weakness");
  script_summary(english:"Does a version check on wfica32.exe.");

  script_set_attribute(attribute:"synopsis", value:
"A client application installed on the remote Windows host is affected
by a man-in-the-middle vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Online Plug-in or ICA Client installed on the
remote Windows host is affected by an unspecified man-in-the-middle
(MitM) vulnerability. This issue is related to Microsoft security
bulletin MS09-056 and is likely due to a failure to detect null bytes
in the common name of a server certificate. A remote attacker can
exploit this issue to perform a man-in-the-middle attack, allowing the
attacker to read or modify SSL/TLS traffic being sent to and from the
host.

This plugin only checks the ICA Client running on Windows, though
other platforms are affected.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS09-056");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX123248");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Online Plug-in or Citrix ICA Client version
11.0.150 / 11.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:online_plug-in_for_windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_require_ports(139, 445, 2690);
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/login", "SMB/password", "SMB/name", "SMB/transport", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if ( hotfix_check_fversion_init() != HCF_OK ) exit(1, "Can't open socket to port "+port+".");
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

path = hotfix_get_programfilesdir() + "\Citrix\ICA Client";
patch1 = hotfix_check_fversion(file:'wfica32.exe', version:'11.0.150.0', path:path);
patch2 = hotfix_check_fversion(file:'wfica32.exe', min_version:'11.1.0.0',      version:"11.2.0.0", path:path);

if (patch1 == HCF_OLDER || patch2 == HCF_OLDER)
{
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}

hotfix_check_fversion_end();

if (patch1 == HCF_OK && patch2 == HCF_OK)
  audit(AUDIT_HOST_NOT, 'affected');
else if (patch1 == HCF_NOENT && patch2 == HCF_NOENT)
  exit(0, "ICA Client doesn't appear to be installed on the remote host.");
else
  exit(1, "Unexpected error (return codes: "+patch1+" "+patch2+").");

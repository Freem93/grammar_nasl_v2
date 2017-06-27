#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62438);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/03/23 03:08:51 $");

  script_cve_id("CVE-2012-2287");
  script_bugtraq_id(55662);
  script_osvdb_id(85727);
  script_xref(name:"IAVB", value:"2012-B-0098");

  script_name(english:"RSA Authentication Client 3.5 < 3.5.6 Local Authentication Bypass");
  script_summary(english:"Checks RSA Authentication Client version");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"RSA Authentication Client, an authentication client from RSA Security,
is installed on the remote Windows host.  The installed version of RSA
Authentication Client 3.5 is earlier than 3.5.6 and is, therefore,
potentially affected by an authentication bypass vulnerability.  Under
certain circumstances, a user who only has access to a desktop or server
could be able to connect with only Windows credentials.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524219/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to RSA Authentication Client 3.5.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:rsa_authentication_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

app = 'RSA Authentication Client';
port = kb_smb_transport();

os = get_kb_item_or_exit("SMB/WindowsVersion");
if (os != '5.1' && os != '5.2')
  audit(AUDIT_OS_SP_NOT_VULN);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\RSA\RSA Authentication Client\CurrentVersion\InstallDir";
path = get_registry_value(handle:hklm, item:key);

if (isnull(path))
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_UNINST, app);
}

key = "SOFTWARE\RSA\RSA Authentication Client\CurrentVersion\ProductVersion";
version = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);
close_registry();
if (isnull(version))
{
  exit(1, "Failed to get the version of " + app + ".");
}

if (version =~ '^3\\.5\\.' && ver_compare(ver:version, fix:'3.5.6.0') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path          : ' + path +
      '\n  Version       : ' + version + 
      '\n  Fixed version : 3.5.6.0\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

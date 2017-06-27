#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62798);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/11/05 11:42:21 $");

  script_cve_id("CVE-2011-2300", "CVE-2011-2305");
  script_bugtraq_id(48781, 48793);
  script_osvdb_id(73896, 73897);

  script_name(english:"Oracle VM VirtualBox 3.x / 4.0.x < 4.0.10 Local Integer Overflows");
  script_summary(english:"Does a version check on VirtualBox.exe");

  script_set_attribute( attribute:"synopsis", value:
"The remote Windows host has an application that is affected by two
local overflow vulnerabilities.");
  script_set_attribute( attribute:"description", value:
"The remote host contains a version of Oracle VM VirtualBox or Sun xVM
VirtualBox 3.0, 3.1, 3.2, or 4.0.x prior to 4.0.10.  As such, it is
reportedly affected by two vulnerabilities :

  - A local user can exploit a flaw in Guest Additions for 
    Windows to gain partial elevated privileges.  This issue
    only affects version 4.0.x. (CVE-2011-2300)

  - A local user can exploit an unspecified flaw to gain 
    full control of the target system. (CVE-2011-2305)");
  #http://www.oracle.com/technetwork/topics/security/cpujuly2011-313328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7c55943");
  #http://mista.nu/blog/2011/07/19/oracle-virtualbox-integer-overflow-vulnerabilities/ 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c54ecc3f");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:"Upgrade to Oracle VM VirtualBox 4.0.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("virtualbox_installed.nasl");
  script_require_keys("VirtualBox/Version");
  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('VirtualBox/Version');
path = get_kb_item_or_exit('SMB/VirtualBox/'+ver);

ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

# Versions 3.0, 3.1, 3.2, 4.0 - 4.0.8 are affected
if (
  (major == 4 && minor == 0 && rev <= 8) || 
  (major == 3 && minor <=2)
)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 4.0.10\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Oracle VM VirtualBox', ver, path);

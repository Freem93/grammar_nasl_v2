#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62100);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/20 16:51:15 $");

  script_cve_id("CVE-2012-3221");
  script_bugtraq_id(55471, 56045);
  script_osvdb_id(86384);

  script_name(english:"Oracle VirtualBox 4.1 < 4.1.22 Task-Gate IDT Call NULL Pointer Dereference Local DoS");
  script_summary(english:"Does a version check on VirtualBox.exe");

  script_set_attribute( attribute:"synopsis", value:
"The remote Windows host has an application that is affected by local
denial of service vulnerabilities.");
  script_set_attribute( attribute:"description", value:
"The remote host contains a version of Oracle VirtualBox 4.1 before
4.1.22.  As such, it is potentially affected by a local denial of
service vulnerability caused by invocation of software interrupt 0x8
from userspace.  An attacker with access to the guest VM could leverage
this to cause a denial of service.");
  # http://www.halfdog.net/Security/2012/VirtualBoxSoftwareInterrupt0x8GuestCrash/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9fa4a738");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cef09be");
  script_set_attribute(attribute:"solution", value:"Upgrade to Oracle VirtualBox 4.1.22 / 4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

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

# Versions 4.1 < 4.1.22 are definitely affected.
if (major == 4 && minor == 1 && rev < 22)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 4.1.22 / 4.2\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else if (
  (major == 3 && minor == 2) ||
  (major == 4 && minor == 0) 
) exit(0, "Nessus is unable to determine if the install of Oracle VirtualBox " + ver + " under " + path + " is affected.");
else audit(AUDIT_INST_PATH_NOT_VULN, 'Oracle VirtualBox', ver, path);

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(63646);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/04/20 02:52:15 $");

  script_cve_id("CVE-2013-0420");
  script_bugtraq_id(57383);
  script_osvdb_id(89249);

  script_name(english:"Oracle VM VirtualBox Core Subcomponent < 4.0.18 / 4.1.24 / 4.2.6 Local Issue");
  script_summary(english:"Does a version check on VirtualBox.exe");

  script_set_attribute( attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a local
vulnerability.");
  script_set_attribute( attribute:"description", value:
"The remote host contains a version of Oracle VM VirtualBox earlier than
4.0.18 / 4.1.24 / 4.2.6.  As such, it is potentially affected by a local
vulnerability that could allow an authenticated attacker to impact
integrity and availability.");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  # http://www.oracle.com/technetwork/topics/security/cpujan2013-1515902.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aac4d874");
  script_set_attribute(attribute:"solution", value:"Upgrade to Oracle VM VirtualBox 4.0.18 / 4.1.24 / 4.2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("virtualbox_installed.nasl");
  script_require_keys("VirtualBox/Version");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

ver = get_kb_item_or_exit('VirtualBox/Version');
path = get_kb_item_or_exit('SMB/VirtualBox/'+ver);

ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

if (
  major == 4 && 
  (
    (minor == 0 && rev < 18) || 
    (minor == 1 && rev < 24)  || 
    (minor == 2 && rev < 6)
  )
)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 4.0.18 / 4.1.24 / 4.2.6\n'; 
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Oracle VM VirtualBox', ver, path);

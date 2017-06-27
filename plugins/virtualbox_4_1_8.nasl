#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62901);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/11/14 21:57:53 $");

  script_cve_id("CVE-2012-0105", "CVE-2012-0111");
  script_bugtraq_id(51461, 51465);
  script_osvdb_id(78442, 78443);

  script_name(english:"Oracle VM VirtualBox 4.1.x < 4.1.8 Unspecified Local Issues");
  script_summary(english:"Does a version check on VirtualBox.exe");

  script_set_attribute( attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
unspecified local vulnerabilities.");
  script_set_attribute( attribute:"description", value:
"The version of Oracle VM VirtualBox 4.1.x installed on the remote
Windows host is earlier than version 4.1.8 and is, therefore, affected
by two unspecified local vulnerabilities. 

These vulnerabilities take advantage of shared folders and Windows Guest
Additions that a local attacker could use to access and modify data that
is accessible by Oracle VM VirtualBox.");
  # http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html#AppendixOVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?035fa4ce");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:"Upgrade to Oracle VM VirtualBox 4.1.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/13");

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

# Versions 4.1 < 4.1.8 are affected
if (major == 4 && minor == 1 && rev < 8)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 4.1.8\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Oracle VM VirtualBox', ver, path);

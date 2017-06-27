#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40549);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2009-2714", "CVE-2009-2715");
  script_bugtraq_id(35915, 35960);
  script_osvdb_id(56810, 56893);
  script_xref(name:"EDB-ID", value:"9323");
  script_xref(name:"Secunia", value:"36080");

  script_name(english:"Sun xVM VirtualBox < 3.0.4 Multiple Local Denial of Service Vulnerabilities");
  script_summary(english:"Does a version check on VirtualBox.exe");

  script_set_attribute( attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
local denial of service vulnerabilities."  );
  script_set_attribute( attribute:"description", value:
"The remote host contains a version of Sun xVM VirtualBox, an open
source virtualization platform, before 3.0.4.  Such versions
have multiple local denial of service vulnerabilities.  A guest
virtual machine (VM) can reboot the host machine by executing the
'sysenter' instruction.  The vendor states there are several other
denial of service vulnerabilities in addition to this.

An attacker with access to the guest VM could leverage these to
cause a denial of service."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.oracle.com/sunalerts/1020812.1.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://forums.virtualbox.org/viewtopic.php?f=1&t=20948"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Sun xVM VirtualBox 3.0.4 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/08/03"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/08/03"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/11"
  );
 script_cvs_date("$Date: 2016/05/19 18:10:50 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:xvm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("virtualbox_installed.nasl");
  script_require_keys("VirtualBox/Version");
  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


ver = get_kb_item('VirtualBox/Version');
if (isnull(ver)) exit(0, "The 'VirtualBox/Version' KB item is missing.");

ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

# Versions < 3.0.4 are affected
if (
  major < 3 ||
  major == 3 && minor == 0 && rev < 4
)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "  Product version    : ", ver, "\n",
      "  Should be at least : 3.0.4\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "Version " + ver + " is not affected.");

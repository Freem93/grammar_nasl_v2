#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73577);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/09/12 18:55:23 $");

  script_cve_id("CVE-2014-2441");
  script_bugtraq_id(66868);
  script_osvdb_id(105919);

  script_name(english:"Oracle VM VirtualBox < 4.1.32 / 4.2.24 / 4.3.10 WDDM Graphics Driver Flaw");
  script_summary(english:"Performs a version check on VirtualBox.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a flaw in the
WDDM graphics driver.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Oracle VM VirtualBox that is
prior to 4.1.32, 4.2.24, or 4.3.10. It is, therefore, potentially
affected by a flaw in the WDDM graphics driver.

A flaw exists in the graphics driver for Windows guests, WDDM. It
could allow local users to affect the confidentiality, integrity, and
availability of the application.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html#AppendixOVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23999f63");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:"Upgrade Oracle VM VirtualBox to 4.1.32 / 4.2.24 / 4.3.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("virtualbox_installed.nasl");
  script_require_keys("VirtualBox/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('VirtualBox/Version');
path = get_kb_item_or_exit('SMB/VirtualBox/'+ver);

# Note int(null) returns '0'
ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

# Affected :
# 4.1.x < 4.1.32
# 4.2.x < 4.2.24
# 4.3.x < 4.3.10
if (major == 4 && minor == 1 && rev < 32) fix = '4.1.32';
else if (major == 4 && minor == 2 && rev < 24) fix = '4.2.24';
else if (major == 4 && minor == 3 && rev < 10) fix = '4.3.10';

if (fix)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Oracle VM VirtualBox', ver, path);

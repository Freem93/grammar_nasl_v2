#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72985);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2014-0981", "CVE-2014-0983");
  script_bugtraq_id(66131, 66132, 66133);
  script_osvdb_id(104352, 104353, 104354);
  script_xref(name:"EDB-ID", value:"32208");

  script_name(english:"Oracle VM VirtualBox < 3.2.22 / 4.0.24 / 4.1.32 / 4.2.24 / 4.3.8 Multiple Memory Corruption");
  script_summary(english:"Performs a version check on VirtualBox.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple memory
corruption vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Oracle VM VirtualBox that is
3.2.x prior to 3.2.22, 4.0.24, 4.1.32, 4.2.24 or 4.3.8. It is,
therefore, potentially affected by the following vulnerabilities :

  - An input validation error exists in the function
    'crNetRecvReadback' in the file
    'GuestHost/OpenGL/util/net.c' related to handling
    CR_MESSAGE_READBACK and CR_MESSAGE_WRITEBACK messages
    that could allow memory corruption leading to
    application crashes and possibly arbitrary code
    execution. (CVE-2014-0981)

  - An input validation error exists related to the
    Chromium server and the handling of
    CR_VERTEXATTRIB4NUBARB_OPCODE messages that could allow
    memory corruption leading to application crashes and
    possibly arbitrary code execution. (CVE-2014-0983)");
  # http://www.coresecurity.com/advisories/oracle-virtualbox-3d-acceleration-multiple-memory-corruption-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1d0f576");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html#AppendixOVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23999f63");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade Oracle VM VirtualBox to 3.2.22 / 4.0.24 / 4.1.32 / 4.2.24 /
4.3.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VirtualBox 3D Acceleration Virtual Machine Escape');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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
# 3.2.x < 3.2.22
# 4.0.x < 4.0.24
# 4.1.x < 4.1.32
# 4.2.x < 4.2.24
# 4.3.x < 4.3.8
if (major == 3 && minor == 2 && rev < 22) fix = '3.2.22';
else if (major == 4 && minor == 0 && rev < 24) fix = '4.0.24';
else if (major == 4 && minor == 1 && rev < 32) fix = '4.1.32';
else if (major == 4 && minor == 2 && rev < 24) fix = '4.2.24';
else if (major == 4 && minor == 3 && rev < 8) fix = '4.3.8';

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

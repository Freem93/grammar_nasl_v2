#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76536);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id(
    "CVE-2014-2477",
    "CVE-2014-2486",
    "CVE-2014-2487",
    "CVE-2014-2488",
    "CVE-2014-2489",
    "CVE-2014-4228",
    "CVE-2014-4261"
  );
  script_bugtraq_id(
    68584,
    68588,
    68601,
    68610,
    68613,
    68618,
    68621
  );
  script_osvdb_id(
    109147,
    109148,
    109149,
    109151,
    109152,
    109153,
    109154
  );

  script_name(english:"Oracle VM VirtualBox < 3.2.24 / 4.0.26 / 4.1.34 / 4.2.26 / 4.3.14 Multiple Unspecified Vulnerabilities");
  script_summary(english:"Performs a version check on VirtualBox.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
unspecified vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Oracle VM VirtualBox that is
prior to 3.2.24, 4.0.26, 4.1.34, 4.2.26 or 4.3.14. It is, therefore,
affected by the following vulnerabilities :

  - An unspecified flaw relating to the Core subcomponent
    that may allow a local attacker to gain elevated
    privileges. (CVE-2014-2487, CVE-2014-4261)

  - An unspecified flaw relating to the Core subcomponent
    that may allow a local attacker to have an impact on
    integrity and availability.
    (CVE-2014-2486, CVE-2014-2477, CVE-2014-2489)

  - An unspecified flaw relating to the Core subcomponent
    that may allow a local attacker to gain access to
    sensitive information. (CVE-2014-2488)

  - An unspecified flaw relating to the Graphics driver
    for Windows guests that may allow a local attacker to
    have an impact on confidentiality, integrity, and
    availability. (CVE-2014-4228)");
  # http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html#AppendixOVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e39c574a");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade Oracle VM VirtualBox to 3.2.24 / 4.0.26 / 4.1.34 / 4.2.26 /
4.3.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VirtualBox Guest Additions VBoxGuest.sys Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:virtualization");

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
# 3.2.x < 3.2.24
# 4.0.x < 4.0.26
# 4.1.x < 4.1.34
# 4.2.x < 4.2.26
# 4.3.x < 4.3.14
if (major == 3 && minor == 2 && rev < 24) fix = '3.2.24';
else if (major == 4 && minor == 0 && rev < 26) fix = '4.0.26';
else if (major == 4 && minor == 1 && rev < 34) fix = '4.1.34';
else if (major == 4 && minor == 2 && rev < 26) fix = '4.2.26';
else if (major == 4 && minor == 3 && rev < 14) fix = '4.3.14';

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

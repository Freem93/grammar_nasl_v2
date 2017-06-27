#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72007);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/04/20 04:29:52 $");

  script_cve_id(
    "CVE-2014-0404",
    "CVE-2014-0405",
    "CVE-2014-0406",
    "CVE-2014-0407"
  );
  script_bugtraq_id(64900, 64905, 64911, 64913);
  script_osvdb_id(102058, 102059, 102060, 102061);

  script_name(english:"Oracle VM VirtualBox < 3.2.20 / 4.0.22 / 4.1.30 / 4.2.20 / 4.3.4 Multiple Vulnerabilities");
  script_summary(english:"Does a version check on VirtualBox.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application that is affected by multiple
security vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host contains a version of Oracle VM VirtualBox prior to
3.2.20 / 4.0.22 / 4.1.30 / 4.2.20 / 4.3.4.  It is, therefore,
potentially affected by multiple, unspecified local security
vulnerabilities related to a flaw in the 'Core' subcomponent."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/530945/30/0/threaded");
  #http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17c46362");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Oracle VM VirtualBox to 3.2.20 / 4.0.22 / 4.1.30 / 4.2.20 /
4.3.4 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/17");

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

ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

if (major == 3 && minor == 2 && rev < 20) fix = '3.2.20';
else if (major == 4 && minor == 0 && rev < 22) fix = '4.0.22';
else if (major == 4 && minor == 1 && rev < 30) fix = '4.1.30';
else if (major == 4 && minor == 2 && rev < 20) fix = '4.2.20';
else if (major == 4 && minor == 3 && rev < 4) fix = '4.3.4';

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
    security_note(port:port, extra:report);
  }
  else security_note(port);

  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Oracle VM VirtualBox', ver, path);

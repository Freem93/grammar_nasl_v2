#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(68984);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/01/26 03:37:38 $");

  script_cve_id("CVE-2013-3792");
  script_bugtraq_id(60794);
  script_osvdb_id(94460);

  script_name(english:"Oracle VM VirtualBox < 3.2.18 / 4.0.20 / 4.1.28 / 4.2.18 Local DoS");
  script_summary(english:"Does a version check on VirtualBox.exe");

  script_set_attribute( attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a local
denial of service vulnerability.");
  script_set_attribute( attribute:"description", value:
"The remote host contains a version of Oracle VM VirtualBox earlier than
3.2.18 / 4.0.20 / 4.1.28 / 4.2.18.  As such, it is potentially affected
by a local denial of service vulnerability when handling a tracepath.");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html#AppendixOVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c273c338");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2013/q3/38");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/ticket/11863");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox to 3.2.18 / 4.0.20 / 4.1.28 / 4.2.18 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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

if (major == 3 && minor == 2 && rev < 18) fix = '3.2.18';
else if (major == 4 && minor == 0 && rev < 20) fix = '4.0.20';
else if (major == 4 && minor == 1 && rev < 28) fix = '4.1.28';
else if (major == 4 && minor == 2 && rev < 18) fix = '4.2.18';

if (fix)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix;
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Oracle VM VirtualBox', ver, path);

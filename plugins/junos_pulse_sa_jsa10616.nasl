#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73057);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/03/26 10:46:23 $");

  script_cve_id("CVE-2014-2292");
  script_bugtraq_id(66379);
  script_osvdb_id(104420);

  script_name(english:"Juniper Junos Pulse Secure Access Service IVE OS (SSL VPN) Linux Network Connect Client Local Privilege Escalation (JSA10616)");
  script_summary(english:"Checks OS version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of Juniper Junos
Pulse Secure Access Service IVE OS running on the remote host serves out
a Network Connect Client, a Java-based VPN client, that is affected by a
local privilege escalation vulnerability when run on Linux end-user
systems."
  );
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10616");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Juniper Junos Pulse Secure Access Service IVE OS version
7.1r17 / 7.3r10 / 7.4r8 / 8.0r2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:ive_os");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_pulse_secure_access_service");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Juniper/IVE OS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('Host/Juniper/IVE OS/Version');
match = eregmatch(string:version, pattern:"^([\d.]+)([Rr](\d+))?");
if (isnull(match)) exit(1, 'Error parsing version: ' + version);

release = match[1];
build = 0;
if (!isnull(match[2])) build = int(match[3]);

if (release == '7.1' && build < 17)
  fix = '7.1r17';
else if (release == '7.3' && build < 10)
  fix = '7.3r10';
else if (release == '7.4' && build < 8)
  fix = '7.4r8';
else if (release == '8.0' && build < 2)
  fix = '8.0r2';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'IVE OS', version);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);

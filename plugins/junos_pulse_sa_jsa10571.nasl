#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69183);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_bugtraq_id(60521);
  script_osvdb_id(94193);

  script_name(english:"Juniper IVE OS Unintentionally Trusted Certificate Authorities");
  script_summary(english:"Checks IVE OS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of IVE OS running
on the remote host has an insecure SSL configuration.  Internal and
development Certificate Authorities (CAs) used by Juniper during testing
were mistakenly included and explicitly trusted in public releases of
IVE OS.  A man-in-the-middle attacker could with access to these CAs
could exploit this to compromise the confidentiality and integrity of
SSL connections without being detected. 

This plugin determines whether or not the system is vulnerable solely by
check the OS version.  It does not check if the workaround in Juniper
Security Advisory JSA10571 is being used."
  );
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10571");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to IVE OS 7.1r7 or later, or use the workaround listed in
Juniper Security Advisory JSA10571."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:ive_os");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_pulse_secure_access_service");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Juniper/IVE OS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('Host/Juniper/IVE OS/Version');
match = eregmatch(string:version, pattern:"^([\d.]+)[Rr](\d+)");
if (isnull(match)) exit(1, 'Error parsing version: ' + version);

release = match[1];
build = int(match[2]);

# the advisory says:
# The issue was seen from IVE OS version 7.1r1 to 7.1r5, 7.0r2 to 7.0r8
if (
  (release == '7.1' && build >= 1 && build <= 5) ||
  (release == '7.0' && build >= 2 && build <= 8)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.1r7\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else
{
  audit(AUDIT_INST_VER_NOT_VULN, 'IVE OS', version);
}

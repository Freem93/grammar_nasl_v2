#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69986);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2014/09/19 16:34:42 $");

  script_cve_id("CVE-2013-5650");
  script_bugtraq_id(62354);
  script_osvdb_id(97241);

  script_name(english:"Junos Pulse Secure IVE / UAC OS DoS (JSA10590)");
  script_summary(english:"Checks IVE/UAC OS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of IVE / UAC OS
running on the remote host may be affected by an unspecified denial of
service vulnerability that can be triggered by sending a specially
crafted packet to the device.  A system restart is required to bring the
device back into service after successful exploitation. 

Note that only devices with the hardware acceleration card are affected
by this issue.  As a workaround, it is possible to mitigate this
vulnerability by disabling the hardware SSL acceleration card.  Nessus
did not verify if the remote device has an SSL acceleration card or if a
workaround has been applied."
  );
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10590");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Juniper IVE/UAC OS version 7.1r5 / 7.2r10 / 7.3r6 / 7.4r3 /
4.1r8.1 / 4.2r5 / 4.3r6 / 4.4r3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:ive_os");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_pulse_access_control_service");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_pulse_secure_access_service");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Juniper/IVE OS/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('Host/Juniper/IVE OS/Version');
match = eregmatch(string:version, pattern:"^([\d.]+)[Rr]([0-9.]+)");
if (isnull(match)) exit(1, 'Error parsing version: ' + version);

release = match[1];
build = match[2];

# check report paranoia settings in order to avoid false positives,
# since a workaround is possible, and only devices with SSL acceleration
# cards are vulnerable
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = '';

# IVE-SA
if (release == '7.1' && ver_compare(ver:build, fix:'5', strict:FALSE) == -1)
  fix = '7.1r5';
if (release == '7.2' && ver_compare(ver:build, fix:'10', strict:FALSE) == -1)
  fix = '7.2r10';
if (release == '7.3' && ver_compare(ver:build, fix:'6', strict:FALSE) == -1)
  fix = '7.3r6';
if (release == '7.4' && ver_compare(ver:build, fix:'3', strict:FALSE) == -1)
  fix = '7.4r3';

# IVE-IC (UAC OS)
if (release == '4.1' && ver_compare(ver:build, fix:'8.1', strict:FALSE) == -1)
  fix = '4.1r8.1';
if (release == '4.2' && ver_compare(ver:build, fix:'5', strict:FALSE) == -1)
  fix = '4.2r5';
if (release == '4.3' && ver_compare(ver:build, fix:'6', strict:FALSE) == -1)
  fix = '4.3r6';
if (release == '4.4' && ver_compare(ver:build, fix:'3', strict:FALSE) == -1)
  fix = '4.4r3';

if (fix != '')
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'IVE/UAC OS', version);

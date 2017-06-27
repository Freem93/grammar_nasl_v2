#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76306);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/30 15:49:04 $");

  script_cve_id("CVE-2014-3812");
  script_bugtraq_id(68192);
  script_osvdb_id(108003);

  script_name(english:"Junos Pulse Secure Access IVE / UAC OS Weak Cipher Information Disclosure (JSA10628)");
  script_summary(english:"Checks IVE/UAC OS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of IVE / UAC OS
running on the remote host is affected by an information disclosure
vulnerability due to an issue where cipher suites with weak encryption
algorithms are used even when cipher suites with strong encryption
algorithms are enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10628");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper Junos IVE OS version 7.4r5 / 8.0r1 or later or UAC
OS version 4.4r5 / 5.0r1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:ive_os");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:unified_access_control_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_pulse_secure_access_service");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_pulse_access_control_service");

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
match = eregmatch(string:version, pattern:"^([0-9.]+)[Rr]([0-9.]+)");
if (isnull(match)) exit(1, 'Error parsing version : ' + version);

release = match[1];
build   = match[2];

# IVE OS
if (release == '7.4' && ver_compare(ver:build, fix:'5', strict:FALSE) == -1)
  fix = '7.4r5';
else if (release == '8.0' && ver_compare(ver:build, fix:'1', strict:FALSE) == -1)
  fix = '8.0r1';

# UAC OS
else if (release == '4.4' && ver_compare(ver:build, fix:'5', strict:FALSE) == -1)
  fix = '4.4r5';
else if (release == '5.0' && ver_compare(ver:build, fix:'1', strict:FALSE) == -1)
  fix = '5.0r1';

else
  audit(AUDIT_INST_VER_NOT_VULN, 'IVE/UAC OS', version);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);

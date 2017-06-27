#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85405);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_osvdb_id(
    126172,
    126173,
    126174,
    126175,
    126176,
    126177,
    126178,
    126179,
    126180
  );

  script_name(english:"Wireshark 1.12.x < 1.12.7 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is
1.12.x prior to 1.12.7. It is, therefore, affected by multiple denial
of service vulnerabilities :

  - An unspecified flaw exists that is triggered when adding
    an item to the protocol tree. A remote attacker can
    exploit this, via a specially crafted packet or packet
    trace file, to cause the application to crash, resulting
    in a denial of service condition. (VulnDB 126172)

  - An invalid memory freeing flaw exists in the Memory
    Manager. A remote attacker can exploit this, via a
    specially crafted packet or packet trace file, to cause
    the application to crash, resulting in a denial of
    service condition. (VulnDB 126173)

  - An unspecified flaw exists when searching for a protocol
    dissector. A remote attacker can exploit this, via a
    specially crafted packet or packet trace file, to cause
    the application to crash, resulting in a denial of
    service condition. (VulnDB 126174)

  - An unspecified flaw exists in the ZigBee dissector. A
    remote attacker can exploit this, via a specially
    crafted packet or packet trace file, to cause the
    application to crash, resulting in a denial of service
    condition. (VulnDB 126175)

  - A flaw exists in the GSM RLC/MAC dissector that results
    in an infinite loop. A remote attacker can exploit this,
    via a specially crafted packet or packet trace file, to
    cause the application to crash, resulting in a denial of
    service condition. (VulnDB 126176)

  - An unspecified flaw exists in the WaveAgent dissector. A
    remote attacker can exploit this, via a specially
    crafted packet or packet trace file, to cause the
    application to crash, resulting in a denial of service
    condition. (VulnDB 126177)

  - A flaw exists in the OpenFlow dissector that results in
    an infinite loop. A remote attacker can exploit this,
    via a specially crafted packet or packet trace file, to
    consume excessive CPU resources, resulting in a denial
    of service condition. (VulnDB 126178)

  - A flaw exists due to improper validation of ptvcursor
    lengths. A remote attacker can exploit this, via a
    specially crafted packet or packet trace file, to cause
    the application to crash, resulting in a denial of
    service condition. (VulnDB 126179)

  - An unspecified flaw exists in the WCCP dissector. A
    remote attacker can exploit this, via a specially
    crafted packet or packet trace file, to cause the
    application to crash, resulting in a denial of service
    condition. (VulnDB 126180)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-21.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-22.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-23.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-24.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-25.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-26.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-27.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-28.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-29.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.7.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.12.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "Wireshark";
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

fixed_version = "1.12.7";

# Affected :
#  1.12.x < 1.12.7
if (version !~ "^1\.12\.[0-6]($|[^0-9])")
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);

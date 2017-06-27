#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70763);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/03/15 02:06:33 $");

  script_cve_id(
    "CVE-2013-6336",
    "CVE-2013-6337",
    "CVE-2013-6338",
    "CVE-2013-6339",
    "CVE-2013-6340"
  );
  script_bugtraq_id(63500, 63501, 63502, 63503, 63504);
  script_osvdb_id(99262, 99275, 99276, 99277, 99278);

  script_name(english:"Wireshark 1.8.x < 1.8.11 Multiple DoS Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.8.x is earlier than 1.8.11.  It
is, therefore, affected by denial of service vulnerabilities in the
following dissectors :

  - IEEE 802.15.4 (Bug #9139)
  - NBAP (Bug #9168)
  - SIP (Bug #9228)
  - ActiveMQ OpenWire (Bug #9248)
  - TCP (Bug #9263)");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-61.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-62.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-63.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-64.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-65.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.11.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.8.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# Check each install.
installs = get_kb_list_or_exit("SMB/Wireshark/*");

info  = '';
info2 = '';

foreach install(keys(installs))
{
  if ("/Installed" >< install) continue;

  version = install - "SMB/Wireshark/";

  if (version =~ "^1\.8\.([0-9]|10)($|[^0-9])")
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.8.11\n';
  else
    info2 += 'Version ' + version + ', under ' + installs[install] + ' ';
}

# Remove trailing space on info2
if (strlen(info2) > 1)
  info2 = substr(info2, 0, strlen(info2) -2);

# Report if any were found to be vulnerable
if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 4) s = "s of Wireshark are";
    else s = " of Wireshark is";

    report =
      '\n' + 'The following vulnerable instance' + s + ' installed :' +
      '\n' +
      info;
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
if (info2) exit(0, "The following installed instance(s) of Wireshark are not affected : " + info2 + ".");

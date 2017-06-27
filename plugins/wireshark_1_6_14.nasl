#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65253);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id(
    "CVE-2012-6054",
    "CVE-2012-6056",
    "CVE-2013-2478",
    "CVE-2013-2480",
    "CVE-2013-2481",
    "CVE-2013-2482",
    "CVE-2013-2483",
    "CVE-2013-2484",
    "CVE-2013-2485",
    "CVE-2013-2488"
  );
  script_bugtraq_id(
    56729,
    58340,
    58351,
    58353,
    58355,
    58356,
    58357,
    58362,
    58365
  );
  script_osvdb_id(
    87995,
    87996,
    90993,
    90994,
    90995,
    90996,
    90997,
    90998,
    90999,
    90100,
    90101,
    90991,
    91000,
    91001
  );

  script_name(english:"Wireshark 1.6.x < 1.6.14 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.6 is earlier than 1.6.14.  It is,
therefore, affected by the following vulnerabilities :

  - Errors exist in the FCSP, AMPQ, SCTP, and sFlow
    dissector that could lead to an infinite loop resulting
    in a denial of service. (Bugs 7789, 7802, 8337, 8359)

  - Errors exist in the CIMD, DTLS, Mount, MS-MMS, RTPS,
    and RTPS2 that could allow them to crash.
    (Bugs 8382, 8332, 8335, 8346, 8380)

  - The ACN dissector can attempt a divide by zero
    operation that could lead to an application crash.
    (Bug 8340)");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-32.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-33.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-13.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-15.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-16.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-17.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-18.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-19.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-20.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-22.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.6.14.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.6.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

  if (version =~ "^1\.6\.([0-9]|1[0-3])($|[^0-9])")
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.6.14\n';
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
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
if (info2) exit(0, "The following installed instance(s) of Wireshark are not affected : " + info2 + ".");

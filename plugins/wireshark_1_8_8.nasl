#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66895);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/01/13 15:34:52 $");

  script_cve_id(
    "CVE-2013-4074",
    "CVE-2013-4075",
    "CVE-2013-4076",
    "CVE-2013-4077",
    "CVE-2013-4078",
    "CVE-2013-4079",
    "CVE-2013-4080",
    "CVE-2013-4081",
    "CVE-2013-4082",
    "CVE-2013-4083"
  );
  script_bugtraq_id(
    60448,
    60495,
    60498,
    60499,
    60500,
    60501,
    60502,
    60503,
    60504,
    60505,
    60506
  );
  script_osvdb_id(
    94086,
    94087,
    94088,
    94090,
    94091,
    94092,
    94093,
    94244,
    94245,
    94246
  );

  script_name(english:"Wireshark 1.8.x < 1.8.8 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.8 is earlier than 1.8.8.  It is,
therefore, affected by the following vulnerabilities :

  - Errors exist in the CAPWAP, DCP ETSI, GSM CBCH, GMR-1 
    BCCH, PPP, NBAP, RDP dissectors that could allow them to
    crash. (Bugs 7664, 7880, 8697, 8717, 8725, 8726, 8727, 
    8729, 8730)

  - An error exists in the Assa Abloy R3 dissector that
    could cause a denial of service, resulting in
    consumption of excessive memory and CPU. (Bug 8764)

  - An error exists in the HTTP dissector that could overrun
    the stack, which could result in an application crash.
    (Bug 8733)

  - An error exists in the Ixia IxVeriWave file parser that
    could overflow the heap, resulting in consumption of
    excessive CPU resources and crash. (Bug 8760)");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-32.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-33.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-34.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-35.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-36.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-37.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-38.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-39.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-40.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-41.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.8.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.8.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

  if (version =~ "^1\.8\.[0-7]($|[^0-9])")
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.8.8\n';
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

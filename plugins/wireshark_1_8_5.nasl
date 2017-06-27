#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64362);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/04/04 15:52:09 $");

  script_cve_id(
    "CVE-2013-1572",
    "CVE-2013-1573",
    "CVE-2013-1574",
    "CVE-2013-1575",
    "CVE-2013-1576",
    "CVE-2013-1577",
    "CVE-2013-1578",
    "CVE-2013-1579",
    "CVE-2013-1580",
    "CVE-2013-1581",
    "CVE-2013-1582",
    "CVE-2013-1583",
    "CVE-2013-1584",
    "CVE-2013-1585",
    "CVE-2013-1586",
    "CVE-2013-1587",
    "CVE-2013-1588",
    "CVE-2013-1589",
    "CVE-2013-1590"
  );
  script_bugtraq_id(
    57615,
    57616,
    57618,
    57619,
    57620,
    57621,
    57622,
    57625,
    57626,
    57647
  );
  script_osvdb_id(
    89664,
    89665,
    89666,
    89667,
    89668,
    89669,
    89670,
    89671,
    89673,
    89674,
    89675,
    89676,
    89677,
    89678,
    89679,
    89680,
    89681,
    89956
  );

  script_name(english:"Wireshark 1.8.x < 1.8.5 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.8 is earlier than 1.8.5.  It is,
therefore, affected by the following vulnerabilities :

  - Errors exist related to the Bluetooth HCI, CSN.1,
    DCP-ETSI DOCSIS CM-STAUS, IEEE 802.3 Slow Protocols,
    MPLS, R3, RTPS, SDP, and SIP dissectors that could
    allow the application to enter infinite or large loops,
    thereby consuming excessive CPU resources. (Bugs 8036,
    8037, 8038, 8040, 8041, 8042, 8043, 8198, 8199, 8222)

  - Errors exist related to the DCP-ETSI, ROHC, DTLS,
    MS-MMC, DTN, CLNP dissectors that could allow them to
    crash. (Bugs 7679, 7871, 7945, 8111, 8112, 8213)

  - An unspecified error could allow the dissection engine
    to crash. (Bug 8197)

  - An unspecified buffer overflow exists in the NTLMSSP
    dissector that has an unspecified impact.");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-01.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-02.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-03.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-04.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-05.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-06.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-07.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-08.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-09.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.5.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.8.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/30");

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

  if (version =~ "^1\.8\.[0-4]($|[^0-9])")
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.8.5\n';
  else
    info2 += 'Version ' + version + ', under ' + installs[install] + ' ';
}

# Remove trailing space on info2
if (strlen(info2) > 1)
  info2 = substr(info2, 0, strlen(info2) -2);

# Report if any were found to be vulnerable
if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 4) s = "s of Wireshark are";
    else s = " of Wireshark is";

    report =
      '\n' + 'The following vulnerable instance' + s + ' installed :' + 
      '\n' + 
      '\n' + info;
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
if (info2) exit(0, "The following installed instance(s) of Wireshark are not affected : " + info2 + ".");

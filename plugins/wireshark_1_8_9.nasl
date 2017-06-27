#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69104);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/01 11:06:37 $");

  script_cve_id(
    "CVE-2013-4927",
    "CVE-2013-4929",
    "CVE-2013-4930",
    "CVE-2013-4931",
    "CVE-2013-4932",
    "CVE-2013-4933",
    "CVE-2013-4934",
    "CVE-2013-4935"
  );
  script_bugtraq_id(61471);
  script_osvdb_id(95713, 95714, 95716, 95718, 95720, 95726, 95727);

  script_name(english:"Wireshark 1.8.x < 1.8.9 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.8 is earlier than 1.8.9.  It is,
therefore, affected by denial of service vulnerabilities in the
following dissectors :

  - ASN.1 PER (Bug #8722)
  - Bluetooth SDP (Bug #8831)
  - DIS (Bug #8911)
  - DVB-CI (Bug #8916)
  - GSM A Common (Bug #8940)
  - GSM RR (Bug #8923)
  - Netmon file parser (Bug #8742)");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-45.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-47.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-48.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-49.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-50.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-51.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2013-52.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.9.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.8.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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

  if (version =~ "^1\.8\.[0-8]($|[^0-9])")
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.8.9\n';
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

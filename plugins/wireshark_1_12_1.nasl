#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77732);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/11/21 15:59:35 $");

  script_cve_id(
    "CVE-2014-6423",
    "CVE-2014-6424",
    "CVE-2014-6425",
    "CVE-2014-6426",
    "CVE-2014-6427",
    "CVE-2014-6428",
    "CVE-2014-6429",
    "CVE-2014-6430",
    "CVE-2014-6431",
    "CVE-2014-6432"
  );
  script_bugtraq_id(
    69853,
    69857,
    69858,
    69859,
    69860,
    69861,
    69862,
    69863,
    69865,
    69866
  );

  script_name(english:"Wireshark 1.12.x < 1.12.1 Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is version 1.12.x prior to 1.12.1.
It is, therefore, affected by the following vulnerabilities :

  - Errors exist in the following dissectors that can cause
    the application to crash :

    - CUPS (CVE-2014-6425)
    - HIP (CVE-2014-6426)
    - MEGACO (CVE-2014-6423)
    - Netflow (CVE-2014-6424)
    - RTSP (CVE-2014-6427)
    - SES (CVE-2014-6428)

  - Unspecified errors exist related to file parsing that
    can cause the parser to crash. (CVE-2014-6429,
    CVE-2014-6430, CVE-2014-6431, CVE-2014-6432)

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-13.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-14.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-15.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-16.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-17.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-18.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-19.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.1.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.12.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_ports("installed_sw/Wireshark", "installed_sw/Ethereal");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "Wireshark";
if (get_install_count(app_name:app_name) == 0)
{
  app_name = "Ethereal";
  if (get_install_count(app_name:app_name) == 0)
    audit(AUDIT_NOT_INST, "Wireshark/Ethereal");
}

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

if (version =~ "^1\.12\.0($|[^0-9])")
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.12.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

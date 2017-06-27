#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80459);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/03/14 19:33:40 $");

  script_cve_id(
    "CVE-2015-0562",
    "CVE-2015-0561",
    "CVE-2015-0563",
    "CVE-2015-0564",
    "CVE-2015-0559",
    "CVE-2015-0560"
  );
  script_bugtraq_id(
    71916,
    71917,
    71918,
    71919,
    71921,
    71922
  );
  script_osvdb_id(
    116808,
    116809,
    116810,
    116811,
    116812,
    116813
  );

  script_name(english:"Wireshark 1.10.x < 1.10.12 / 1.12.x < 1.12.3 Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Wireshark installed that is
1.10.x prior to 1.10.12 or 1.12.x prior to 1.12.3. It is, therefore,
affected by multiple denial of service vulnerabilities in the
following dissectors :

  - DEC DNA Routing (CVE-2015-0562)
  - LPP (CVE-2015-0561)
  - SMTP (CVE-2015-0563)
  - WCCP (CVE-2015-0559, CVE-2015-0560)

  - A denial of service vulnerability also exists related to
    a buffer underflow error in TLS/SSL session decryption.
    (CVE-2015-0564)

A remote attacker, using a specially crafted packet or malformed pcap
file, can exploit these to cause the application to crash.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-01.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-02.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-03.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-04.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-05.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.10.12.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.3.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.10.12 / 1.12.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

fixed_version = FALSE;

# Affected :
#  1.10.x < 1.10.12
#  1.12.x < 1.12.3
if (version =~ "^1\.10\.(\d|1[01])($|[^0-9])")
  fixed_version = "1.10.12";
else if (version =~ "^1\.12\.[0-2]($|[^0-9])")
  fixed_version = "1.12.3";
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

if (fixed_version)
{
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
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87824);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/02 15:47:18 $");

  script_cve_id(
    "CVE-2015-8711",
    "CVE-2015-8712",
    "CVE-2015-8713",
    "CVE-2015-8714",
    "CVE-2015-8715",
    "CVE-2015-8716",
    "CVE-2015-8717",
    "CVE-2015-8718",
    "CVE-2015-8719",
    "CVE-2015-8720",
    "CVE-2015-8721",
    "CVE-2015-8722",
    "CVE-2015-8723",
    "CVE-2015-8724",
    "CVE-2015-8725",
    "CVE-2015-8726",
    "CVE-2015-8727",
    "CVE-2015-8728",
    "CVE-2015-8729",
    "CVE-2015-8730",
    "CVE-2015-8731",
    "CVE-2015-8732",
    "CVE-2015-8733"
  );
  script_osvdb_id(
    131887,
    131888,
    131892,
    131894,
    131896,
    131897,
    131898,
    131899,
    131900,
    131901,
    132140,
    132143,
    132406,
    132407,
    132416,
    132418,
    132419,
    132420,
    132421,
    132422,
    132423,
    132424,
    132425,
    132468
  );
  script_xref(name:"EDB-ID", value:"38995");
  script_xref(name:"EDB-ID", value:"38996");
  script_xref(name:"EDB-ID", value:"38999");
  script_xref(name:"EDB-ID", value:"39000");
  script_xref(name:"EDB-ID", value:"39001");
  script_xref(name:"EDB-ID", value:"39002");
  script_xref(name:"EDB-ID", value:"39003");
  script_xref(name:"EDB-ID", value:"39004");
  script_xref(name:"EDB-ID", value:"39005");
  script_xref(name:"EDB-ID", value:"39006");
  script_xref(name:"EDB-ID", value:"39076");
  script_xref(name:"EDB-ID", value:"39077");

  script_name(english:"Wireshark 1.12.x < 1.12.9 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is
1.12.x prior to 1.12.9. It is, therefore, affected by multiple
denial of service vulnerabilities in the following components :

  - 802.11 dissector
  - AllJoyn dissector
  - ANSI A dissector
  - Ascend file parser
  - BER dissector
  - DCOM dissector
  - DIAMETER dissector
  - DNS dissector
  - GSM A dissector
  - NBAP dissector
  - NLM dissector
  - RSL dissector
  - RSVP dissector
  - SCTP dissector
  - SDP dissector
  - Sniffer file parser
  - T.38 dissector
  - UMTS FP dissector
  - VeriWave file parser
  - ZigBee ZCL dissector
  - zlib compression

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.9.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.12.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

# Affected :
#  1.12.x < 1.12.9
if (version !~ "^1\.12\.[0-8]($|[^0-9])")
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 1.12.9' +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);

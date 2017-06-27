#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87825);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/02 15:47:18 $");

  script_cve_id(
    "CVE-2015-8711",
    "CVE-2015-8718",
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
    "CVE-2015-8733",
    "CVE-2015-8734",
    "CVE-2015-8735",
    "CVE-2015-8736",
    "CVE-2015-8737",
    "CVE-2015-8738",
    "CVE-2015-8739",
    "CVE-2015-8740",
    "CVE-2015-8741",
    "CVE-2015-8742"
  );
  script_osvdb_id(
    131887,
    131888,
    131889,
    131890,
    131891,
    131892,
    131893,
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
    132408,
    132409,
    132410,
    132411,
    132416,
    132417,
    132421,
    132422
  );
  script_xref(name:"EDB-ID", value:"38993");
  script_xref(name:"EDB-ID", value:"38994");
  script_xref(name:"EDB-ID", value:"38995");
  script_xref(name:"EDB-ID", value:"38996");
  script_xref(name:"EDB-ID", value:"38997");
  script_xref(name:"EDB-ID", value:"38998");
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

  script_name(english:"Wireshark 2.0.0 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is
2.0.0. It is, therefore, affected by multiple denial of service
vulnerabilities in the following components :

  - 802.11 dissector
  - ANSI A dissector
  - Ascend file parser
  - BER dissector
  - Bluetooth Attribute dissector
  - DIAMETER dissector
  - GSM A dissector
  - IPMI dissector
  - MP2T file parser
  - MS-WSP dissector
  - NBAP dissector
  - NLM dissector
  - NWP dissector
  - PPI dissector
  - RSL dissector
  - RSVP dissector
  - S7COMM dissector
  - SCTP dissector
  - Sniffer file parser
  - TDS dissector
  - VeriWave file parser
  - ZigBee ZCL dissector
  - zlib compression

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/25");
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
#  2.0.0 < 2.0.1
if (version !~ "^2\.0\.0($|[^0-9])")
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 2.0.1' +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);

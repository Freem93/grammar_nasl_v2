#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59684);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/11 13:32:17 $");

  script_cve_id(
    "CVE-2009-3555",
    "CVE-2010-2227",
    "CVE-2010-4470",
    "CVE-2010-4476",
    "CVE-2011-0611",
    "CVE-2011-0786",
    "CVE-2011-0788",
    "CVE-2011-0802",
    "CVE-2011-0814",
    "CVE-2011-0815",
    "CVE-2011-0817",
    "CVE-2011-0862",
    "CVE-2011-0863",
    "CVE-2011-0864",
    "CVE-2011-0865",
    "CVE-2011-0866",
    "CVE-2011-0867",
    "CVE-2011-0868",
    "CVE-2011-0869",
    "CVE-2011-0871",
    "CVE-2011-0872",
    "CVE-2011-0873",
    "CVE-2011-2092",
    "CVE-2011-2093",
    "CVE-2011-2130",
    "CVE-2011-2134",
    "CVE-2011-2135",
    "CVE-2011-2136",
    "CVE-2011-2137",
    "CVE-2011-2138",
    "CVE-2011-2139",
    "CVE-2011-2140",
    "CVE-2011-2414",
    "CVE-2011-2415",
    "CVE-2011-2416",
    "CVE-2011-2417",
    "CVE-2011-2425",
    "CVE-2011-2426",
    "CVE-2011-2427",
    "CVE-2011-2428",
    "CVE-2011-2429",
    "CVE-2011-2430",
    "CVE-2011-2444",
    "CVE-2011-2445",
    "CVE-2011-2450",
    "CVE-2011-2451",
    "CVE-2011-2452",
    "CVE-2011-2453",
    "CVE-2011-2454",
    "CVE-2011-2455",
    "CVE-2011-2456",
    "CVE-2011-2457",
    "CVE-2011-2458",
    "CVE-2011-2459",
    "CVE-2011-2460",
    "CVE-2011-2461",
    "CVE-2011-3556",
    "CVE-2011-3557",
    "CVE-2011-3558",
    "CVE-2012-1995",
    "CVE-2012-1996",
    "CVE-2012-1997",
    "CVE-2012-1998",
    "CVE-2012-1999"
  );
  script_bugtraq_id(
    36935,
    41544,
    42817,
    46091,
    46387,
    47314,
    48133,
    48134,
    48135,
    48136,
    48137,
    48138,
    48139,
    48140,
    48141,
    48142,
    48143,
    48144,
    48145,
    48146,
    48147,
    48148,
    48149,
    48267,
    48279,
    49073,
    49074,
    49075,
    49076,
    49077,
    49079,
    49080,
    49081,
    49082,
    49083,
    49084,
    49085,
    49086,
    49710,
    49714,
    49715,
    49716,
    49717,
    49718,
    50618,
    50619,
    50620,
    50621,
    50622,
    50623,
    50624,
    50625,
    50626,
    50627,
    50628,
    50629,
    50869,
    53315
  );
  script_osvdb_id(
    66319,
    70965,
    71615,
    71686,
    73008,
    73009,
    73069,
    73070,
    73071,
    73072,
    73073,
    73074,
    73075,
    73076,
    73077,
    73078,
    73079,
    73080,
    73081,
    73082,
    73083,
    73084,
    73085,
    73176,
    74432,
    74433,
    74434,
    74435,
    74436,
    74437,
    74438,
    74439,
    74440,
    74441,
    74442,
    74443,
    74444,
    75625,
    75626,
    75627,
    75628,
    75629,
    75630,
    76505,
    76506,
    76510,
    77018,
    77019,
    77020,
    77021,
    77022,
    77023,
    77024,
    77025,
    77026,
    77027,
    77028,
    77029,
    77425,
    81650,
    81651,
    81652,
    81653,
    81654,
    81655
  );
  script_xref(name:"HP", value:"HPSBMU02769");
  script_xref(name:"HP", value:"SSRT100846");
  script_xref(name:"HP", value:"SSRT100093");
  script_xref(name:"HP", value:"SSRT090028");
  script_xref(name:"HP", value:"SSRT100110");
  script_xref(name:"HP", value:"SSRT100373");
  script_xref(name:"HP", value:"SSRT100426");
  script_xref(name:"HP", value:"SSRT100514");
  script_xref(name:"HP", value:"SSRT100562");
  script_xref(name:"HP", value:"SSRT100639");
  script_xref(name:"HP", value:"SSRT100702");
  script_xref(name:"HP", value:"SSRT100819");

  script_name(english:"HP Systems Insight Manager < 7.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HP Systems Insight Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains software that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP Systems Insight Manager installed on the remote
Windows host is affected by vulnerabilities in the following
components :

  - TLS and SSL protocols
  - Apache Tomcat
  - Java
  - Flash Player
  - BlazeDS/GraniteDS
  - Adobe LiveCycle
  - Adobe Flex SDK
  - Systems Insight Manager");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89accd5e");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP Systems Insight Manager 7.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player MP4 SequenceParameterSetNALUnit Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/09"); 
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:systems_insight_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_systems_insight_manager_installed.nasl");
  script_require_keys("installed_sw/HP Systems Insight Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

app_name = "HP Systems Insight Manager";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

install = get_single_install(app_name:app_name);
path = install['path'];
version = install['version'];

if (version =~ '^(([A-Z]\\.)?0[0-5]\\.|([A-C]\\.)?0[0-6]\\.[0-9\\.]+)')
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  set_kb_item(name:'www/0/XSRF', value:TRUE);

  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : C.07.00.00.00' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

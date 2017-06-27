#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97576);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/05/16 19:26:21 $");

  script_cve_id("CVE-2017-5638");
  script_bugtraq_id(96729);
  script_osvdb_id(153025);
  script_xref(name:"IAVA", value:"2017-A-0052");
  script_xref(name:"CERT", value:"834067");
  script_xref(name:"EDB-ID", value:"41570");
  script_xref(name:"EDB-ID", value:"41614");

  script_name(english:"Apache Struts 2.3.5 - 2.3.31 / 2.5.x < 2.5.10.1 Jakarta Multipart Parser RCE");
  script_summary(english:"Checks the Struts 2 version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web application that uses a Java framework
that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote host is 2.3.5
through 2.3.31 or else 2.5.x prior to 2.5.10.1. It is, therefore,
affected by a remote code execution vulnerability in the Jakarta
Multipart parser due to improper handling of the Content-Type,
Content-Disposition, and Content-Length headers. An unauthenticated,
remote attacker can exploit this, via a specially crafted header value
in the HTTP request, to potentially execute arbitrary code.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html");
  # https://threatpost.com/apache-struts-2-exploits-installing-cerber-ransomware/124844/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77e9c654");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.5.10.1");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.3.32");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-045");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-046");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.32 / 2.5.10.1 or later.
Alternatively, apply the workaround referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts Jakarta Multipart Parser OGNL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl","struts_detect_win.nbin","struts_detect_nix.nbin");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("installed_sw/Apache Struts","installed_sw/Struts");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Apache Struts";

if (report_paranoia < 2) audit(AUDIT_PARANOID);

install = get_single_install(
  app_name : app,
  exit_if_unknown_ver : TRUE
);

version = install['version'];
path  = install['path'];
appname = install['Application Name'];

report = NULL;

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_APP_VER, ("the " + app + " application, " + appname + ", found at " + path + ","));

if (version =~ "^2\.3($|[^0-9])")
{
  min = "2.3.5";
  fix = "2.3.32";
}
else if (version =~ "^2\.5($|[^0-9])")
{
  min = "2.5.0";
  fix = "2.5.10.1";
}

if (ver_compare(ver:version, minver:min, fix:fix, strict:FALSE) < 0)
{
  report +=
    '\n  Application       : ' + appname +
    '\n  Physical path     : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

  os = get_kb_item_or_exit("Host/OS");
  if ('windows' >< tolower(os))
  {
    port = get_kb_item('SMB/transport');
    if (!port) port = 445;
  }
  else port = 0;

  security_report_v4(
    extra    : report,
    port     : port,
    severity : SECURITY_HOLE
  );
}
else audit(AUDIT_INST_PATH_NOT_VULN, (app + " 2 application, " + appname + ","), version, path);

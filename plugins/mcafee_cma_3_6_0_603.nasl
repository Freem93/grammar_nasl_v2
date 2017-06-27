#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42871);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id("CVE-2008-1855");
  script_bugtraq_id(28573);
  script_osvdb_id(44161);
  script_xref(name:"Secunia", value:"29637");
  script_xref(name:"EDB-ID", value:"5343");

  script_name(english:"McAfee Common Management Agent < 3.6.0.603 FrameworkService.exe AVClient DoS");
  script_summary(english:"Checks the version of McAfee CMA.");

  script_set_attribute(attribute:"synopsis", value:
"A security management service running on the remote host is affected
by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the McAfee Common Management
Agent (CMA) running on the remote host is prior to 3.6.0.603. It is,
therefore, affected by a denial of service vulnerability in
FrameworkService.exe due to a memory corruption issue. An
unauthenticated, remote attacker can exploit this, via a long invalid
method in requests to the /spin//AVClient//AVClient.csp URI, to cause
the CMA Framework Service to crash.");
   # http://visibleprocrastinations.wordpress.com/2008/11/28/common-management-agent-3x-epolicy-orchestrator-agent-3x/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d17be0b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Common Management Agent version 3.6.0 Patch 3 with
HotFix 10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/23");

  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:common_management_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "mcafee_cma_detect.nasl");
  script_require_ports("Services/www", 8081);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:8081, embedded: 1);
appname = "McAfee Agent";

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
ver = install['version'];

ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);
update = int(ver_fields[3]);

if (major == 3 && minor == 6 && rev == 0 && update < 603)
{

  report = "
  Installed version : " + ver + "
  Fixed version     : 3.6.0.603";
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "McAfee Common Management Agent", port, ver);


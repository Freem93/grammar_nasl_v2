#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31732);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id("CVE-2008-1357");
  script_bugtraq_id(28228);
  script_osvdb_id(42853);
  script_xref(name:"Secunia", value:"29337");
  script_xref(name:"EDB-ID", value:"31399");

  script_name(english:"McAfee Common Management Agent < 3.6.0.595 UDP Packet Handling Format String");
  script_summary(english:"Checks the version of McAfee CMA.");

  script_set_attribute(attribute:"synopsis", value:
"A security management service running on the remote host is affected
by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of McAfee Common Management Agent
(CMA) running on the remote host is prior to 3.6.0.595. It is,
therefore, affected by a flaw in the logDetail() function of
applib.dll due to calling vsnwprintf() without the needed format
string argument. An unauthenticated, remote attacker can exploit this,
via a specially crafted UDP packet, to cause a denial of service
condition or the execution of arbitrary code. This issue only occurs
when the debug level is set to 8 (the highest level but not the
default). Note that Nessus has not checked the debug level setting,
only the version number in the agent's banner.");
  script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/meccaffi-adv.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/489476/100/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Apply Hotfix BZ398370 Build 595 for McAfee Common Management Agent
version 3.6.0 Patch 3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(134);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:common_management_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_cma_detect.nasl");
  script_require_ports("Services/www", 8081);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

# nb: only run the check if reporting is paranoid since we
#     can't determine the log level setting remotely.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

appname = "McAfee Agent";
port = get_http_port(default:8081, embedded: 1);

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
ver = install['version'];

ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);
update = int(ver_fields[3]);

fix = '';

# There's a problem if the version is under 3.6.0.595.
if (major < 3 ||
   (major == 3 && minor < 6) ||
   (major == 3 && minor == 6 && rev == 0 && update < 595))
  fix = '3.6.0.595';

if(fix != '')
{

  report =
    '\n  Installed Version : ' + ver +
    '\n  Fixed Version     : ' + fix + '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);

}
else audit(AUDIT_LISTEN_NOT_VULN, "McAfee Common Management Agent", port, ver);

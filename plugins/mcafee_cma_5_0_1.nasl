#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83953);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id("CVE-2015-2053");
  script_bugtraq_id(74873);
  script_osvdb_id(118643);
  script_xref(name:"MCAFEE-SB", value:"SB10094");
  script_xref(name:"IAVA", value:"2015-A-0129");

  script_name(english:"McAfee Agent 4.6.x < 4.8.0.1938 / 5.0.x < 5.0.1 Log View Clickjacking (SB10094)");
  script_summary(english:"Checks the version of McAfee Framework Service.");

  script_set_attribute(attribute:"synopsis", value:
"A security management service running on the remote host is affected
by a clickjacking vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the McAfee Agent (MA) running
on the remote host is 4.6.x prior to 4.8.0.1938 or 5.0.x prior to
5.0.1. It is, therefore, affected by a clickjacking vulnerability in
the log viewing feature due to improper validation of user-supplied
input. A remote attacker can exploit this, via a crafted web page, to
compromise the application or obtain sensitive information.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10094");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Agent version 4.8.0 Patch 3 (4.8.0.1938) / 5.0.1 or
later. Alternatively, as a workaround, it is possible to partially
mitigate the vulnerability by adjusting the Agent policy to only allow
connections from the ePO server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:mcafee_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_cma_detect.nasl");
  script_require_ports("Services/www", 8081);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

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

if ((major == 4 && minor >= 6 && minor < 8) ||
    (major == 4 && minor == 8 && rev == 0 && update < 1938)
) fix = '4.8.0.1938';

if (major == 5 && minor == 0 && rev == 0)
  fix = '5.0.1';

if (!empty(fix))
{

  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);

}
else audit(AUDIT_LISTEN_NOT_VULN, "McAfee Common Management Agent", port, ver);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70398);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2013-3627");
  script_bugtraq_id(62785);
  script_osvdb_id(98050);
  script_xref(name:"CERT", value:"613886");
  script_xref(name:"MCAFEE-SB", value:"SB10055");

  script_name(english:"McAfee Managed Agent FrameworkService.exe Denial of Service (SB10055) (credentialed check)");
  script_summary(english:"Checks version of McAfee Framework Service");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a service installed that is affected by a denial of
service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the version of the McAfee Agent installed on the remote
host, it is affected by a denial of service vulnerability that can be
triggered by a specially crafted HTTP request.  Successful exploitation
will cause the FrameworkService.exe service to crash.

Note: This plugin does not check for the presence of any mitigations,
such as setting the policy to limit connections only from the ePO
server."
  );
  script_set_attribute(attribute:"see_also", value:"http://kc.mcafee.com/corporate/index?page=content&id=SB10055");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the correct patches according to the vendor's advisory.

As a workaround, it is possible to partially mitigate the vulnerability
by adjusting the Agent policy to only allow connections from the ePO
server."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:common_management_agent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_cma_installed.nbin");
  script_require_keys("installed_sw/McAfee Agent");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = "McAfee Agent";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);

ver  = install['version'];
path = install['path'];

fix = '';

if (ver_compare(ver:ver, fix:"4.5", strict:FALSE) == -1)
  fix = "4.8.0";

if (ver =~ "^4\.5(\.|$)" && ver_compare(ver:ver, fix:"4.5.0.1927", strict:FALSE) == -1)
  fix = "4.5.0.1927";

if (ver =~ "^4\.6(\.|$)" && ver_compare(ver:ver, fix:"4.6.0.3258", strict:FALSE) == -1)
  fix = "4.6.0.3258";

if (fix != '')
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path );

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81106);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2015-0921", "CVE-2015-0922");
  script_bugtraq_id(71881, 72298);
  script_osvdb_id(116855, 116930);
  script_xref(name:"MCAFEE-SB", value:"SB10095");

  script_name(english:"McAfee ePolicy Orchestrator 4.x <  4.6.9 / 5.x < 5.1.2 Multiple Vulnerabilities (SB10095)");
  script_summary(english:"Checks the version of ePolicy Orchestrator.");

  script_set_attribute(attribute:"synopsis", value:
"A security management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee ePolicy Orchestrator (ePO) installed on the
remote Windows host is 4.x prior to 4.6.9 or 5.x prior to 5.1.2. It
is, therefore, affected by multiple vulnerabilities :

  - An XXE (XML External Entity) injection vulnerability
    exists in the Server Task Log due to an incorrectly
    configured XML parser accepting XML external entities
    from an untrusted source. A remote, authenticated
    attacker, by sending specially crafted XML data via the
    'conditionXML' parameter, can gain access to arbitrary
    files. (CVE-2015-0921)

  - An information disclosure vulnerability exists due to
    the use of a shared secret key to encrypt password
    information. A remote attacker with knowledge of the key
    can decrypt the administrator password. (CVE-2015-0922)");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10095");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2015/Jan/37");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee ePO version 4.6.9 / 5.1.2 or later, or apply the
vendor-supplied workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_epo_installed.nasl");
  script_require_keys("SMB/mcafee_epo/Path", "SMB/mcafee_epo/ver");
  script_require_ports("SMB/transport", 139, 445);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "McAfee ePO";
version = get_kb_item_or_exit("SMB/mcafee_epo/ver");
path =  get_kb_item_or_exit("SMB/mcafee_epo/Path");
port = get_kb_item_or_exit("SMB/transport");
patch = FALSE;
vuln = FALSE;

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Network Associates\ePolicy Orchestrator\InstallFolder";

path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);
if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app_name);
}

orig_path = path;

if ('PROGRA~' >< path)
{
  path = ereg_replace(string:path, pattern:"PROGRA~\d+", replace:"Program Files");
  path = ereg_replace(string:path, pattern:"EPOLIC~\d+", replace:"ePolicy Orchestrator");
}
properties = path + "Server\webapps\core\WEB-INF\mvcactions.xml";
workaround = hotfix_get_file_contents(properties);
err_res = hotfix_handle_error(error_code:workaround['error'], file:properties, exit_on_fail:FALSE);
if (!isnull(err_res))
{
  arch = get_kb_item_or_exit('SMB/ARCH');;
  if (arch == "x64")
  {
    path = orig_path;
    if ('PROGRA~' >< path)
    {
      path = ereg_replace(string:path, pattern:"PROGRA~\d+", replace:"Program Files (x86)");
      path = ereg_replace(string:path, pattern:"EPOLIC~\d+", replace:"ePolicy Orchestrator");
    }
    properties = path + "Server\webapps\core\WEB-INF\mvcactions.xml";
    workaround = hotfix_get_file_contents(properties);
    err_res = hotfix_handle_error(error_code:workaround['error'], file:properties, exit_on_fail:TRUE);
  }
}
hotfix_check_fversion_end();

#
# See Mitigation for ePO 4.6.x and 5.x.x servers:
# https://kc.mcafee.com/corporate/index?page=content&id=SB10095
# Check <ePO_installation_directory>\Server\webapps\core\WEB-INF directory for
# mvcactions.xml, then look for a line containing the following :
# -
# workaround no applied
# <action name="orionUpdateTableFilter.do" execute="updateFilter" checkSecurityToken="true"/>
# +
# workaround applied
# <!-- <action name="orionUpdateTableFilter.do" execute="updateFilter" checkSecurityToken="true"/> -->
#

data = workaround['data'];
pattern = '<!-- <action name=\"orionUpdateTableFilter.do\" execute=\"updateFilter\" checkSecurityToken=\"true\"/> -->';
item = eregmatch(pattern:pattern, string:data);
if (!isnull(item))
{
  patch = TRUE;
}

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_APP_VER, app_name);

if (version =~ "^4\.[56]\." && ver_compare(ver:version, fix:"4.6.9", strict:FALSE) == -1)
  vuln = TRUE;

if (version =~ "^5\.[01]\." && ver_compare(ver:version, fix:"5.1.2", strict:FALSE) == -1)
  vuln = TRUE;

if (patch == FALSE && vuln == TRUE)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installation Path : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : See solution.\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

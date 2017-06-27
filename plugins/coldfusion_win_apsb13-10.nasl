#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65928);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/23 21:23:02 $");

  script_cve_id("CVE-2013-1387", "CVE-2013-1388");
  script_bugtraq_id(58974, 58975);
  script_osvdb_id(92134, 92135);

  script_name(english:"Adobe ColdFusion Multiple Vulnerabilities (APSB13-10) (credentialed check)");
  script_summary(english:"Checks hotfix files");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote Windows host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of ColdFusion that is
affected by the following vulnerabilities :

  - An unspecified user impersonation vulnerability.
    (CVE-2013-1387)

  - An unspecified vulnerability that allows unauthorized
    access to the administrator console. (CVE-2013-1388)");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-10.html");
  # http://helpx.adobe.com/coldfusion/kb/coldfusion-security-hotfix-apsb13-10.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f34a67f7");
  script_set_attribute(attribute:"solution", value:"Apply the relevant hotfixes referenced in Adobe advisory APSB13-10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_keys("SMB/coldfusion/instance");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("coldfusion_win.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

versions = make_list('9.0.0', '9.0.1', '9.0.2', '10.0.0');
instances = get_coldfusion_instances(versions); # this exits if it fails

# Check the hotfixes and cumulative hotfixes installed for each
# instance of ColdFusion.
info = NULL;
instance_info = make_list();

# a connection needs to be made to the system in order to call check_cfide_hotfix()
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

cfide_file = "\CFIDE\adminapi\administrator.cfc";
searchterm = 'setAdminAPI';

foreach name (keys(instances))
{
  info = NULL;
  ver = instances[name];

  if (ver == "9.0.0")
  {
    info = check_cfide_hotfix(name, cfide_file, searchterm, 'CFIDE-9.zip');
    remove = make_list("00001", "00002", "00003", "00004", "00005", "00006", "00007", "00008", "00009");
    info += check_jar_hotfix(name, "00010", 2, remove);
  }
  else if (ver == "9.0.1")
  {
    info = check_cfide_hotfix(name, cfide_file, searchterm, 'CFIDE-901.zip');
    remove = make_list("00001", "00002", "00003", "00004", "00005", "00006", "00007", "00008");
    info += check_jar_hotfix(name, "00009", 3, remove);
  }
  else if (ver == "9.0.2")
  {
    info = check_cfide_hotfix(name, cfide_file, searchterm, 'CFIDE-902.zip');
    remove = make_list("00001", "00002", "00003");
    info += check_jar_hotfix(name, "00004", 1, remove);
  }
  else if (ver == "10.0.0")
  {
    # CF10 uses an installer for updates so it is less likely (perhaps not possible) to only partially install a hotfix.
    # this means the plugin doesn't need to check for anything in the CFIDE directory, it just needs to check the CHF level
    info = check_jar_chf(name, 9);
  }

  if (!isnull(info))
    instance_info = make_list(instance_info, info);
}

NetUseDel();

if (max_index(instance_info) == 0)
  exit(0, "No vulnerable instances of Adobe ColdFusion were detected.");

port = kb_smb_transport();

if (report_verbosity > 0)
{
  report =
    '\nNessus detected the following unpatched instances :' +
    '\n' + join(instance_info, sep:'\n') +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);

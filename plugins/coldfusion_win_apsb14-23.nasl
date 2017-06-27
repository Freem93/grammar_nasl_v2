#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78480);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2014-0570", "CVE-2014-0571", "CVE-2014-0572");
  script_bugtraq_id(70433, 70435, 70438);
  script_osvdb_id(113193, 113194, 113195);

  script_name(english:"Adobe ColdFusion Multiple Vulnerabilities (APSB14-23) (credentialed check)");
  script_summary(english:"Checks the hotfix files.");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote Windows host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote Windows host
is affected by the following vulnerabilities :

  - An unspecified cross-site request forgery vulnerability
    exists because ColdFusion does not properly sanitize
    user-supplied input. (CVE-2014-0570)

  - An unspecified cross-site scripting vulnerability exists
    because ColdFusion does not properly sanitize
    user-supplied input. (CVE-2014-0571)

  - ColdFusion is affected by a security permissions issue
    which can allow a local, unauthenticated user to bypass
    IP address access control restrictions.
    (CVE-2014-0572)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb14-23.html");
  # http://helpx.adobe.com/coldfusion/kb/coldfusion-security-hotfix-apsb14-23.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad49a4b6");
  script_set_attribute(attribute:"solution", value:"Apply the relevant hotfixes referenced in Adobe advisory APSB14-23.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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

versions = make_list('9.0.0', '9.0.1', '9.0.2', '10.0.0', '11.0.0');
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

if (!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

cfide_file = "\CFIDE\administrator\logviewer\_searchloglogic_other.cfm";
searchterm = 'doFinally';

foreach name (keys(instances))
{
  info = NULL;
  ver = instances[name];

  if (ver == "9.0.0")
  {
    info = check_cfide_hotfix(name, cfide_file, searchterm, 'CFIDE-9.zip');
    remove = make_list("00001", "00002", "00003", "00004", "00005", "00006", "00007", "00008", "00009", "00010", "00011", "00012");
    info += check_jar_hotfix(name, "00013", 2, remove);
  }
  else if (ver == "9.0.1")
  {
    info = check_cfide_hotfix(name, cfide_file, searchterm, 'CFIDE-901.zip');
    remove = make_list("00001", "00002", "00003", "00004", "00005", "00006", "00007", "00008", "00009", "00010", "00011");
    info += check_jar_hotfix(name, "00012", 3, remove);
  }
  else if (ver == "9.0.2")
  {
    info = check_cfide_hotfix(name, cfide_file, searchterm, 'CFIDE-902.zip');
    remove = make_list("00001", "00002", "00003", "00004", "00005", "00006");
    info += check_jar_hotfix(name, "00007", 1, remove);
  }
  if (ver == "10.0.0")
  {
    # CF10 uses an installer for updates so it is less likely (perhaps not possible) to only partially install a hotfix.
    # this means the plugin doesn't need to check for anything in the CFIDE directory, it just needs to check the CHF level
    info = check_jar_chf(name, 14);
  }
  else if (ver == "11.0.0")
  {
    info = check_jar_chf(name,2);
  }

  if (!isnull(info))
    instance_info = make_list(instance_info, info);
}

NetUseDel();

if (max_index(instance_info) == 0) exit(0, "No vulnerable instances of Adobe ColdFusion were detected.");

set_kb_item(name:'www/0/XSS', value:TRUE);
set_kb_item(name:'www/0/XSRF', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus detected the following unpatched instances :' +
    '\n' + join(instance_info, sep:'\n') +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);

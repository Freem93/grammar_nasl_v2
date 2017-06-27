#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66526);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/17 21:38:53 $");

  script_cve_id(
    "CVE-2013-0625",
    "CVE-2013-0629",
    "CVE-2013-0631",
    "CVE-2013-0632"
  );
  script_bugtraq_id(57164, 57165, 57166, 57330);
  script_osvdb_id(88888, 88889, 88890, 89096);
  script_xref(name:"EDB-ID", value:"24946");
  script_xref(name:"EDB-ID", value:"27755");

  script_name(english:"Adobe ColdFusion Multiple Vulnerabilities (APSB13-03) (credentialed check)");
  script_summary(english:"Checks for hotfixes");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote Windows host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote host is missing
hotfixes that address the following vulnerabilities :

  - An authentication bypass vulnerability exists that could
    allow an unauthorized user to gain administrative
    access. (CVE-2013-0625)

  - A directory traversal vulnerability exists that could
    allow an unauthorized user to gain administrative
    access. (CVE-2013-0629)

  - An unspecified information disclosure vulnerability
    exists that affects servers that have already been
    compromised. (CVE-2013-0631)

  - Authentication bypass vulnerability exists that could
    allow an unauthorized user to gain administrative
    access. (CVE-2013-0632)");
  script_set_attribute(attribute:"see_also", value:"http://forums.adobe.com/message/4962104");
  # http://www.carehart.org/blog/client/index.cfm/2013/1/2/Part2_serious_security_threat
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?832b0298");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa13-01.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-03.html");
  # http://helpx.adobe.com/coldfusion/kb/coldfusion-security-hotfix-apsb13-03.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7a32ae4");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfixes referenced in Adobe security bulletin
APSB13-03.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe ColdFusion 9 Administrative Login Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
;# forum post# APSB13-03

script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/28");  
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/15"); 
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/21");

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
searchterm = 'isRdsEnabled';

foreach name (keys(instances))
{
  info = NULL;
  ver = instances[name];

  if (ver == "9.0.0")
  {
    info = check_cfide_hotfix(name, cfide_file, searchterm, 'CFIDE-9.zip');
    remove = make_list("00001", "00002", "00003", "00004", "00005", "00006", "00007", "00008");
    info += check_jar_hotfix(name, "00009", 2, remove);
  }
  else if (ver == "9.0.1")
  {
    info = check_cfide_hotfix(name, cfide_file, searchterm, 'CFIDE-901.zip');
    remove = make_list("00001", "00002", "00003", "00004", "00005", "00006", "00007");
    info += check_jar_hotfix(name, "00008", 3, remove);
  }
  else if (ver == "9.0.2")
  {
    info = check_cfide_hotfix(name, cfide_file, searchterm, 'CFIDE-902.zip');
    remove = make_list("00001", "00002");
    info += check_jar_hotfix(name, "00003", 1, remove);
  }
  else if (ver == "10.0.0")
  {
    # CF10 uses an installer for updates so it is less likely (perhaps not possible) to only partially install a hotfix.
    # this means the plugin doesn't need to check for anything in the CFIDE directory, it just needs to check the CHF level
    info = check_jar_chf(name, 7);
  }

  if (!isnull(info))
    instance_info = make_list(instance_info, info);
}

NetUseDel();

if (max_index(instance_info) == 0)
  exit(0, "No vulnerable instances of Adobe ColdFusion were detected.");

if (report_verbosity > 0)
{
  report =
    '\nNessus detected the following unpatched instances :' +
    '\n' + join(instance_info, sep:'\n') +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);

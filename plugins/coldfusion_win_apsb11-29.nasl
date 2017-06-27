#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57362);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/23 21:23:02 $");

  script_cve_id("CVE-2011-2463", "CVE-2011-4368");
  script_bugtraq_id(51039, 51043);
  script_osvdb_id(77721, 77722);

  script_name(english:"Adobe ColdFusion XSS Vulnerabilities (APSB11-29) (credentialed check)");
  script_summary(english:"Checks for hotfix file");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote Windows host is affected
by multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote Windows host is
affected by multiple cross-site scripting vulnerabilities. Successful
exploitation of these issues may allow an attacker to execute
malicious script code in a user's browser within the context of the
affected website.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-29.html");
  script_set_attribute(attribute:"see_also", value:"http://kb2.adobe.com/cps/925/cpsid_92512.html");
  script_set_attribute(attribute:"solution", value:"Apply the relevant hotfixes referenced in the Adobe advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_keys("SMB/coldfusion/instance");
  script_require_ports(139, 445);

  exit(0);
}

include("coldfusion_win.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");

# Get details of ColdFusion installs.
instances = get_kb_list("SMB/coldfusion/instance");
if (isnull(instances)) exit(0, "Adobe ColdFusion is not installed on the remote host.");

# Compile a list of the relevant ColdFusion versions installed on the host.
inst_to_check = make_list();
foreach instance (instances)
{
  ver = get_kb_item("SMB/coldfusion/" + instance + "/version");
  if (ver == "8.0.0" || ver == "8.0.1" || ver == "9.0.0" || ver == "9.0.1")
    inst_to_check = make_list(inst_to_check, instance);
}

if (max_index(inst_to_check) == 0)
  exit(0, "None of the affected versions of Adobe ColdFusion are installed.");

port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();


# Try to connect to server.
if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Check the hotfixes and cumulative hotfixes installed for each
# instance of ColdFusion.
info = NULL;
instance_info = make_list();

foreach instance (inst_to_check)
{
  info = NULL;

  if (ver == "8.0.0")
    info = check_jar_hotfix(instance, "00004", 4, make_list("00001", "00002", "00003",
           "1875", "1878", "70523", "71471", "73122", "77218"));
  else if (ver == "8.0.1")
    info = check_jar_hotfix(instance, "00004", 5, make_list("00001", "00002", "00003",
           "1875", "1878", "71471", "73122", "77218"));
  else if (ver == "9.0.0")
    info = check_jar_hotfix(instance, "00004", 2, make_list("00001", "00002", "00003"));
  else if (ver == "9.0.1")
    info = check_jar_hotfix(instance, "00003", 3, make_list("00001","00002"));

  if (!isnull(info))
    instance_info = make_list(instance_info, info);
}

NetUseDel();

if (max_index(instance_info) == 0)
  exit(0, "No vulnerable instances of Adobe ColdFusion were detected.");

# the hotfix corrects XSS vulns
set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\nNessus detected the following unpatched instances :' +
    '\n' + join(instance_info, sep:'\n') +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);

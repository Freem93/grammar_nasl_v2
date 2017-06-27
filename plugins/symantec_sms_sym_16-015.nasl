#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(93652);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2016-5309", "CVE-2016-5310");
  script_bugtraq_id(92866, 92868);
  script_osvdb_id(144639, 144640);
  script_xref(name:"IAVA", value:"2016-A-0254");
  script_xref(name:"IAVA", value:"2016-A-0255");

  script_name(english:"Symantec Mail Security for Exchange and Domino Decomposer Engine Multiple DoS (SYM16-015)");
  script_summary(english:"Checks the version of Dec2.dll.");

  script_set_attribute(attribute:"synopsis", value:
"A security application installed on the remote host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Mail Security for Exchange (SMSMSE) or
Symantec Mail Security for Domino (SMSDOM) installed on the remote
Windows host is affected by multiple denial of service vulnerabilities
in the decomposer engine :

  - A denial of service vulnerability exists in the
    decomposer engine due to an out-of-bounds read error
    that occurs when decompressing RAR archives. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted RAR file, to crash the application.
    (CVE-2016-5309)

  - A denial of service vulnerability exists in the
    decomposer engine due to memory corruption issue that
    occurs when decompressing RAR archives. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted RAR file, to crash the application.
    (CVE-2016-5310)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160919_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4125a0d");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/en_US/article.INFO3793.html");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/en_US/article.INFO3794.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security_for_microsoft_exchange");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security_for_domino");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("sms_for_domino.nasl", "sms_for_msexchange.nasl");
  script_require_keys("Symantec_Mail_Security/Installed");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit("Symantec_Mail_Security/Installed");

types = make_list("Domino", "Exchange");

# Ensure that the affected software is installed.
backend = NULL;
foreach type (types)
{
  if (get_kb_item("SMB/SMS_" + type + "/Installed"))
  {
    backend = type;
    break;
  }
}
if (empty_or_null(backend) || (backend != 'Exchange' && backend != 'Domino'))
  audit(AUDIT_NOT_INST, "Symantec Mail Security for Domino or Exchange");

path    = get_kb_item_or_exit("SMB/SMS_" + type + "/Path");
version = get_kb_item_or_exit("SMB/SMS_" + type + "/Version");

app       = 'Symantec Mail Security for ' + backend;
dec2_fix  = "5.4.7.5";
dec2_path = NULL;

ver = split(version, sep:'.', keep:FALSE);
branch = ver[0] + '.' + ver[1];

if (backend == 'Exchange' && branch =~ "^(6\.5|7\.[05])")
  dec2_path = "\SMSMSE\" + branch + "\Server\";
else if (backend == 'Domino' && branch =~ "^8\.[01]")
  dec2_path = "\Decomposer\"; 

if (isnull(dec2_path)) audit(AUDIT_INST_PATH_NOT_VULN, app, branch, path);

dec2_path = hotfix_append_path(path:path, value:dec2_path + "Dec2.dll");
dec2_ver = hotfix_get_fversion(path:dec2_path);
hotfix_handle_error(error_code:dec2_ver['error'], file:dec2_path, exit_on_fail:TRUE);
hotfix_check_fversion_end();

dec2_ver = join(dec2_ver['value'], sep:'.');

if (ver_compare(ver:dec2_ver, fix:dec2_fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, app + " decomposer engine", dec2_ver, path);

port = get_kb_item('SMB/transport');
if (isnull(port)) port = 445;

report =
  '\n  Product                             : ' + app + ' ' + branch +
  '\n  Path                                : ' + path +
  '\n  Installed decomposer engine version : ' + dec2_ver +
  '\n  Fixed decomposer engine version     : ' + dec2_fix +
  '\n';

security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);

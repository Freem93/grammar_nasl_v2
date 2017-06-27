#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67003);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/06 17:22:01 $");

  script_cve_id("CVE-2007-0447", "CVE-2007-3699");
  script_bugtraq_id(24282);
  script_osvdb_id(36118, 36119);

  script_name(english:"Symantec Mail Security for SMTP RAR and CAB Parsing Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Symantec Mail Security for SMTP");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a heap overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Symantec Mail Security for
Exchange / Domino that is affected by multiple vulnerabilities :

  - A heap overflow vulnerability exists that can be
    triggered when the scanning engine processes a specially
    crafted CAB file, possibly leading to arbitrary code
    execution. (CVE-2007-0447)

  - It is is possible to trigger a denial of service
    condition when the scanning engine processes a RAR file
    with a specially crafted header. (CVE-2007-3699)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-040/");
  # http://www.symantec.com/business/support/index?page=content&id=TECH102208
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?02420ead");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2007.07.11f.html");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate updates per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("sms_smtp_installed.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Registry/Enumerated", "Symantec/SMSSMTP/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

app = "Symantec Mail Security for SMTP";

port = kb_smb_transport();

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Make sure the SMS for SMTP service is running, unless we're
# being paranoid.
if (report_paranoia < 2)
{
  services = get_kb_item("SMB/svcs");
  if (
    !services ||
    ("SMSTomcat" >!< services && "Symantec Mail Security for SMTP" >!< services)
  )
  exit(0, 'Symantec Mail Security for SMTP is not running.');
}

version = get_kb_item_or_exit("Symantec/SMSSMTP/Version");
path = get_kb_item_or_exit('SMB/Symantec/SMSSMTP/' + version);

if (version != "5.0.0" && version != "5.0.1" && version !~ "^4\.")
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

if (version =~ "^4\.")
{
  if (ver_compare(ver:version, fix:"4.1.16", strict:FALSE) == -1)
  {
    if (report_verbosity > 0)
    {
      report = '\n  Path              : ' + path +
               '\n  Installed version : ' + version +
               '\n  Fixed version     : 4.1.16' +
               '\n';
      security_hole(extra:report, port:port);
    }
    else security_hole(port);
    exit(0);
  }
  else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
}

dll = '';

if (path[strlen(path) - 1] == '\\')
  dll = path + "scanner\bin\libdayzero.dll";
else
  dll = path + "\scanner\bin\libdayzero.dll";

ver = hotfix_get_fversion(path:dll);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT)
  audit(AUDIT_UNINST, app);
else if (ver['error'] != HCF_OK)
  audit(AUDIT_VER_FAIL, path);

dll_ver = join(ver['value'], sep:'.');

if (version == "5.0.0")
{
  if (ver_compare(ver:dll_ver, fix:"5.0.0.176", strict:FALSE) == -1)
  {
    if (report_verbosity > 0)
    {
      report = '\n  Path              : ' + path +
               '\n  Installed version : ' + dll_ver +
               '\n  Fixed version     : 5.0.0.176' +
               '\n';
      security_hole(extra:report, port:port);
    }
    else security_hole(port);
    exit(0);
  }
  else audit(AUDIT_INST_PATH_NOT_VULN, app, dll_ver, path);
}
else # version = 5.0.1
{
  if (ver_compare(ver:dll_ver, fix:"5.0.1.181", strict:FALSE) == -1)
  {
    if (report_verbosity > 0)
    {
      report = '\n  Path              : ' + path +
               '\n  Installed version : ' + dll_ver +
               '\n  Fixed version     : 5.0.1.181' +
               '\n';
      security_hole(extra:report, port:port);
    }
    else security_hole(port);
    exit(0);
  }
  else audit(AUDIT_INST_PATH_NOT_VULN, app, dll_ver, path);
}

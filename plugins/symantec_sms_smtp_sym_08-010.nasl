#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68936);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id(
    "CVE-2007-5399",
    "CVE-2007-5405",
    "CVE-2007-5406",
    "CVE-2007-6020",
    "CVE-2008-0066",
    "CVE-2008-1101"
  );
  script_bugtraq_id(28454);
  script_osvdb_id(
    44191,
    44192,
    44193,
    44194,
    44195,
    44196,
    88202,
    88203,
    88204,
    88338,
    88339
  );
  script_xref(name:"IAVB", value:"2008-B-0039");

  script_name(english:"Symantec Mail Security for SMTP Autonomy KeyView Module Multiple Buffer Overflows");
  script_summary(english:"Checks the version of Symantec Mail Security for SMTP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by multiple
buffer overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote windows host has a version of Symantec Mail Security
installed that is shipped with the third-party Autonomy KeyView module,
which is affected by multiple buffer overflow vulnerabilities that could
allow a remote attacker to execute arbitrary code."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2008.04.08e.html");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate patch per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

get_kb_item_or_exit("SMB/Registry/Enumerated");

port = kb_smb_transport();

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

if (version != "5.0.0" && version != "5.0.1")
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

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

if (ver_compare(ver:dll_ver, fix:"5.0.1.189", strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Path              : ' + path +
             '\n  Installed version : ' + dll_ver +
             '\n  Fixed version     : 5.0.1.189' +
             '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, dll_ver, path);

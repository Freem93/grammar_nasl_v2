#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36162);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id("CVE-2008-5731", "CVE-2009-0681");
  script_bugtraq_id(32991, 34490);
  script_osvdb_id(50914, 53678, 53679);

  script_name(english:"PGP Desktop < 9.10 Multiple Local DoS");
  script_summary(english:"Checks version of pgpdisk.sys");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PGP Desktop installed on the remote system is older than
9.10.  As such, it reportedly is affected by the following issues :

  - The IOCTL handler in 'pgpdisk.sys' fails to perform
    sufficient boundary checks on data associated with 'Irp'
    objects. A local attacker could exploit this flaw to
    crash the system.

  - The IOCTL handler in 'pgpwded.sys' fails to perform
    sufficient boundary checks on data associated with 'Irp'
    objects. A local attacker could exploit this flaw to
    crash the system or execute arbitrary code with SYSTEM
    privileges.");
  script_set_attribute(attribute:"see_also", value:"http://en.securitylab.ru/lab/PT-2009-01");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2009/Apr/120");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PGP Desktop version 9.10, which reportedly addresses these
issues.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:pgp:desktop_for_windows");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:encryption_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("pgp_desktop_installed.nasl");
  script_require_keys("SMB/symantec_encryption_desktop/DriverVersion");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("global_settings.inc");
include("misc_func.inc");

app = 'PGP Desktop Disk Encryption Driver';
kb_base = "SMB/symantec_encryption_desktop/";
port = kb_smb_transport();

driver_version = get_kb_item_or_exit(kb_base + "DriverVersion");
path = get_kb_item_or_exit(kb_base + "DriverPath");
path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+$', replace:"\1", string:path);

fix = "9.10";
if (ver_compare(ver:driver_version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + driver_version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, driver_version, path);

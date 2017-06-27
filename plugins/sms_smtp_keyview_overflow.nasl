#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40871);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/09 21:04:55 $");

  script_cve_id("CVE-2009-3037");
  script_bugtraq_id(36042);
  script_osvdb_id(57334);
  script_xref(name:"Secunia", value:"36421");
  script_xref(name:"IAVB", value:"2009-B-0042");

  script_name(english:"Symantec Mail Security for SMTP KeyView Excel SST Parsing RCE");
  script_summary(english:"Does a version check on SMSSMTP.");

  script_set_attribute(  attribute:"synopsis",  value:
"An email security application running on the remote Windows host is
affected by a remote code execution vulnerability.");
  script_set_attribute(  attribute:"description",  value:
"The version of Symantec Mail Security for SMTP running on the remote
host is affected by an integer overflow condition when parsing a
Shared String Table (SST) record inside of an Excel file. One of the
fields in the SST is a 32-bit integer used to specify the size of a
dynamic memory allocation. This integer is not validated, which can
result in a heap-based buffer overflow condition. A remote attacker
can exploit this by tricking a user into viewing an email with a
specially crafted Excel file, resulting in the execution of arbitrary
code as SYSTEM.");
  # https://web.archive.org/web/20150126142007/http://www.verisigninc.com/en_US/cyber-security/security-intelligence/vulnerability-reports/articles/index.xhtml?id=823
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72cc3878");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2009&suid=20090825_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e25c6dae");
  script_set_attribute(attribute:"solution", value:
"Apply patch level 205.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("sms_smtp_installed.nasl");
  script_require_keys("Symantec/SMSSMTP/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

ver = get_kb_item('Symantec/SMSSMTP/Version');
if (isnull(ver)) exit(1, "The 'Symantec/SMSSMTP/Version' KB item is missing.");

ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);

# Only the 5.0.x branch is affected
if (major != 5 && minor != 0) exit(0, "Version "+ver+" is not affected.");

path_key = 'SMB/Symantec/SMSSMTP/' + ver;
path = get_kb_item(path_key);
if (isnull(path)) exit(1, "The '"+path_key+"' KB item is missing.");

dll_path = path + "\scanner\rules\verity";
dll_file = "xlssr.dll";

res = hotfix_check_fversion(file:dll_file, version:"10.4.0.0", path:dll_path);

# After a vanilla install, there is no version in the metadata of the affected
# file
if (res == HCF_OLDER || res == HCF_NOVER)
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}

hotfix_check_fversion_end();
if (res != HCF_OK) exit(1, "Unable to do version check (error code: " + res + ").");
else audit(AUDIT_HOST_NOT, 'affected');

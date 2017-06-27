#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(68935);
  script_version("$Revision: 1.7 $");
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

  script_name(english:"Symantec Mail Security for Exchange / Domino Autonomy KeyView Module Multiple Buffer Overflows");
  script_summary(english:"Checks the version of Symantec Mail Security for Exchange / Domino");

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
which is affected by multiple buffer overflow vulnerabilities.  These
issues could allow a remote attacker to execute arbitrary code."
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

  script_dependencies("sms_for_domino.nasl", "sms_for_msexchange.nasl");
  script_require_keys("Symantec_Mail_Security/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("Symantec_Mail_Security/Installed");

dirs = make_list("Domino", "Exchange");

port = get_kb_item('SMB/transport');
if (isnull(port)) port = 445;

# Ensure that the affected software is installed.
backend = NULL;
foreach type (dirs)
{
  if (get_kb_item("SMB/SMS_" + type + "/Installed"))
  {
    backend = type;
    break;
  }
}
if (isnull(backend) || (backend != 'Exchange' && backend != 'Domino'))
  exit(0, "Symantec Mail Security for Domino or Exchange was not detected on the remote host.");

path = get_kb_item_or_exit("SMB/SMS_" + type + "/Path");
version = get_kb_item_or_exit("SMB/SMS_" + type + "/Version");

if (
  (
    backend == 'Exchange'  &&
    version =~ '^5\\.0\\.' &&
    ver_compare(ver:version, fix:'5.0.10.382', strict:FALSE) == -1
  )
  ||
  (
    backend == 'Domino'    &&
    version =~ '^7\\.5\\.' &&
    ver_compare(ver:version, fix:'7.5.3.25', strict:FALSE) == -1
  )
)
{
  # Report our findings.
  if (report_verbosity > 0)
  {
    if (backend == 'Exchange') fix = '5.0.10.382';
    else fix = '7.5.3.25';
    report =
      '\n  Product           : Symantec Mail Security for ' + backend +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, 'Symantec Mail Security for ' + backend,
        version, path);

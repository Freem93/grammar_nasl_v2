#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(67004);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/06 17:22:01 $");

  script_cve_id("CVE-2007-0447", "CVE-2007-3699");
  script_bugtraq_id(24282);
  script_osvdb_id(36118, 36119);

  script_name(english:"Symantec Mail Security for Exchange / Domino RAR and CAB Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Symantec Mail Security for Exchange / Domino");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a heap overflow vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
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
    backend == 'Exchange' &&
    (
      (version =~ '^6\\.0\\.' && ver_compare(ver:version, fix:'6.0.1', strict:FALSE) == -1) ||
      (version =~ '^5\\.0\\.' && ver_compare(ver:version, fix:'5.0.4', strict:FALSE) <= 0) ||
      (version =~ '^4\\.6\\.' && ver_compare(ver:version, fix:'4.6.7', strict:FALSE) <= 0)
    )
  ) ||
  (
    backend == 'Domino' &&
    (
      (version =~ '^4\\.1\\.' &&
       ver_compare(ver:version, fix:'4.1.5', strict:FALSE) <= 0) ||
      (version =~ '^5\\.1\\.' &&
       ver_compare(ver:version, fix:'5.1.2.28', strict:FALSE) <= 0)
    )
  )
)
{
  # Report our findings.
  if (report_verbosity > 0)
  {
    if (backend == 'Exchange') fix = '6.0.1 / 5.0.5 / 4.6.8.120';
    else fix = '5.1.4.32 / 4.1.9.37';
    report =
      '\n  Product           : Symantec Mail Security for ' + backend +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, 'Symantec Mail Security for ' + backend,
        version, path);

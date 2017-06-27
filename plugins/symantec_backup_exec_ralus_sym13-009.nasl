#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69262);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id("CVE-2013-4575");
  script_bugtraq_id(61485);
  script_osvdb_id(95938);
  script_xref(name:"IAVA", value:"2013-A-0156");

  script_name(english:"Symantec Backup Exec RALUS Code Execution (SYM13-009)");
  script_summary(english:"Checks version of Symantec Backup Exec RALUS");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a backup agent installed that is affected by a code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Backup Exec RALUS installed on the remote host
is 2010 earlier than 2010 R3 SP3, or 2012 earlier than 2012 SP2.  Such
versions are potentially affected by a heap overflow vulnerability.  By
exploiting this flaw, a remote, unauthenticated attacker could execute
arbitrary code on the host subject to the privileges of the user running
the affected application.");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20130801_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd76cf64");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Backup Exec RALUS 2010 R3 SP3, 2012 SP2 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:veritas_backup_exec");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_backup_exec_ralus_installed.nasl");
  script_require_keys("SSH/Symantec Backup Exec RALUS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SSH/Symantec Backup Exec RALUS/Version");
path = get_kb_item_or_exit("SSH/Symantec Backup Exec RALUS/Path");

fix = '';
if (version =~ '^13\\.' && ver_compare(ver:version, fix:'13.0.5204.1225') < 0) fix = '13.0.5204.1225 (2010 R3 SP3)';
else if (version =~ '^14\\.' && ver_compare(ver:version, fix:'14.0.1798.1244') < 0) fix = '14.0.1798.1244 (2012 SP2)';

if (fix)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Symantec Backup Exec RALUS', version, path);

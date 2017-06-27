#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69934);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/09/19 10:58:30 $");

  script_cve_id("CVE-2009-4211");
  script_bugtraq_id(37200);
  script_osvdb_id(60798);
  script_xref(name:"CERT", value:"433821");
  script_xref(name:"IAVA", value:"2009-A-0136");

  script_name(english:"DISA Security Readiness Review Scripts for Solaris Local Privilege Escalation");
  script_summary(english:"Checks versions of scripts");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is affected by a local privilege escalation
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a copy of the DISA Security Readiness Review
(SRR) Scripts for Solaris that is affected by a local privilege
escalation vulnerability.  The vulnerability could be leveraged to
execute files in arbitrary directories with root privileges, as long as
such files are named 'java', 'openssl', 'php', 'snort', 'tshark',
'vncserver', or 'wireshark'."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to a version of the SRR scripts dated December 18, 2009 or
later."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:disa:srr_for_solaris");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "disa_unix_srr_installed.nasl");
  script_require_keys('DISA_SRR/Installed');

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("datetime.inc");

get_kb_item_or_exit('DISA_SRR/Installed');

# The issue only affects Solaris x86 per DISA.
if (report_paranoia < 2)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Solaris" >!< os) audit(AUDIT_OS_NOT, "Solaris");

  showrev = get_kb_item_or_exit("Host/Solaris/showrev");
  if (!egrep(pattern:"^Application architecture: i[3-6]86", string:showrev)) audit(AUDIT_ARCH_NOT, "x86");
}

report = '';
audit_errors = '';
num_installs = get_kb_item_or_exit('DISA_SRR/num_instances');

for (i=0; i<num_installs; i++)
{
  path = get_kb_item_or_exit('DISA_SRR/' + i + '/Path');
  version = get_kb_item_or_exit('DISA_SRR/' + i + '/Version');

  # ex: 29July2011
  item = eregmatch(pattern:"^[^-]+-(\d+)([A-Za-z]+)(\d{4})$", string:version);
  if (isnull(item))
  {
    audit_errors += '\nUnable to parse version string for scripts at \'' + path + '\'';
    continue;
  }

  month = month_num_by_name(item[2]) + 1;
  if (isnull(month))
  {
    audit_errors += '\nError parsing month name for version \'' + version + '\'';
    continue;
  }
  day = int(item[1]);
  year = int(item[3]);

  # Fix: December 18, 2009
  if (
    year < 2009 ||
    (year == 2009 && month < 12) ||
    (year == 2009 && month == 12 && day < 18)
  )
  {
    report += '\n  Path               : ' + path +
              '\n  Current version    : ' + version +
              '\n  Fixed version date : December 18, 2009\n';
  }
}

if (report == '')
{
  if (audit_errors != '') exit(1, audit_errors);
  audit(AUDIT_INST_VER_NOT_VULN, 'DISA Unix Security Readiness Review Scripts');
}

if (audit_errors != '')
  report += '\nNote, additional affected versions may have been missed due to the' +
            '\nfollowing errors :\n' + audit_errors + '\n';

if (report_verbosity > 0) security_warning(extra:report, port:0);
else security_warning(0);

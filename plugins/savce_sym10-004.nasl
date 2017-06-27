#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69956);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/09/20 10:56:15 $");

  script_cve_id("CVE-2010-0106", "CVE-2010-0107", "CVE-2010-0108");
  script_bugtraq_id(38217, 38219, 38222);
  script_osvdb_id(62412, 62413, 62414);
  script_xref(name:"IAVA", value:"2010-A-0036");

  script_name(english:"Symantec AntiVirus Multiple Vulnerabilities (SYM10-002 / SYM10-003 / SYM10-004)");
  script_summary(english:"Checks version of Symantec Antivirus");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a program that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Antivirus Corporate Edition (SAVCE) or Symantec
Client Security is potentially affected by multiple vulnerabilities :

  - If Symantec Tamper protection is disabled, it is
    possible to bypass scanning. (CVE-2010-0106)

  - A browser-based input validation issue exists in
    SYMLTCOM.dll that can lead to a buffer overflow.
    (CVE-2010-0107)

  - A buffer overflow exists in the Symantec Client Proxy,
    'CLIproxy.dll'. (CVE-2010-0108)");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2010&suid=20100217_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?123c355b");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2010&suid=20100217_01
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e29ac7a");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2010&suid=20100217_02
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87ec81ff");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Client Security 3.1 MR9, Symantec AntiVirus 10.1
MR9, Symantec AntiVirus 10.2 MR4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:antivirus");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:client_security");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("savce_installed.nasl");
  script_require_keys("Antivirus/SAVCE/version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

prod_ver = get_kb_item_or_exit("Antivirus/SAVCE/version");

latest_prod_ver = '';
if (prod_ver =~ '^10\\.[01]\\.' && ver_compare(ver:prod_ver, fix:'10.1.9.9000') < 0) latest_prod_ver = '10.1.9.9000';
else if (prod_ver =~ '^10\\.2\\.' && ver_compare(ver:prod_ver, fix:'10.2.4.4000') < 0) latest_prod_ver = '10.2.4.4000';

if (latest_prod_ver)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + prod_ver +
      '\n  Fixed version     : ' + latest_prod_ver + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, prod_ver);

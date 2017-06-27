#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97661);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/03/24 14:10:48 $");

  script_cve_id("CVE-2016-9093", "CVE-2016-9094");
  script_bugtraq_id(96294, 96298);
  script_osvdb_id(153043, 153044);
  script_xref(name:"IAVA", value:"2017-A-0076");

  script_name(english:"Symantec Endpoint Protection Client 12.1.x < 12.1 RU6 MP7 / 14.0.x < 14.0 MP1 Multiple Vulnerabilities (SYM17-002)");
  script_summary(english:"Checks the SEP Client version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Symantec Endpoint Protection Client installed on the
remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection (SEP) Client installed on
the remote host is 12.1 prior to 12.1 RU6 MP7 or 14.0 prior to 14.0
MP1. It is, therefore, affected by multiple vulnerabilities :

  - A local privilege escalation vulnerability exists in the
    SymEvent driver due to improper validation of
    user-supplied input. A local attacker can exploit this,
    via a specially crafted file, to manipulate certain
    system calls, resulting in a denial of service
    condition, or on 64-bit machines only, the execution of
    arbitrary code with kernel privileges. Note that this
    vulnerability does not affect SEP 14.0. (CVE-2016-9093)

  - A flaw exists when handling quarantine logs due to file
    metadata being improperly interpreted and evaluated as a
    formula when exporting logs in .CSV format. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to open a specially crafted file, to
    inject malicious formulas in exported .CSV quarantine
    logs. (CVE-2016-9094)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20170306_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a546db1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Client version 12.1 RU6 MP7 /
14.0 MP1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("savce_installed.nasl");
  script_require_keys("Antivirus/SAVCE/version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");

app = 'Symantec Endpoint Protection Client';

display_ver = get_kb_item_or_exit('Antivirus/SAVCE/version');
edition = get_kb_item('Antivirus/SAVCE/edition');

if (isnull(edition)) edition = '';
else if (edition == 'sepsb') app += ' Small Business Edition';

if (display_ver =~ "^12\.1\.")
  fixed_ver = '12.1.7166.6700';
else if (display_ver =~ "^14\.0\.")
  fixed_ver = '14.0.2332.0100';
else
  audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);

if (ver_compare(ver:display_ver, fix:fixed_ver, strict:FALSE) == -1)
{
  port = kb_smb_transport();

  report =
    '\n  Product           : ' + app +
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);

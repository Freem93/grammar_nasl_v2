#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93717);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2016-5309", "CVE-2016-5310");
  script_bugtraq_id(92866, 92868);
  script_osvdb_id(144639, 144640);
  script_xref(name:"IAVA", value:"2016-A-0258");

  script_name(english:"Symantec Endpoint Protection Client 12.1.x < 12.1.6 MP6 Multiple DoS (SYM16-015)");
  script_summary(english:"Checks the SEP Client version.");

  script_set_attribute(attribute:"synopsis", value:
"A security application installed on the remote host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection (SEP) Client installed on
the remote Windows host is 12.1.x prior to 12.1.6 MP6 or else
12.1.6 MP5 without a hotfix. It is, therefore, affected by multiple
denial of service vulnerabilities :

  - A denial of service vulnerability exists in the
    decomposer engine due to an out-of-bounds read error
    that occurs when decompressing RAR archives. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted RAR file, to crash the application.
    (CVE-2016-5309)

  - A denial of service vulnerability exists in the
    decomposer engine due to memory corruption issue that
    occurs when decompressing RAR archives. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted RAR file, to crash the application.
    (CVE-2016-5310)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160919_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4125a0d");
  # https://support.symantec.com/en_US/article.INFO3934.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a8a9978");
  # https://support.symantec.com/en_US/article.INFO3900.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6d8f403");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection (SEP) Client version 12.1.6
MP6 or later. Alternatively, for version 12.1.6 MP5, apply the
vendor-supplied hotfix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("savce_installed.nasl");
  script_require_keys("Antivirus/SAVCE/version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

app = 'Symantec Endpoint Protection Client';
fix = NULL;

display_ver = get_kb_item_or_exit('Antivirus/SAVCE/version');
edition = get_kb_item('Antivirus/SAVCE/edition');
hotfix_applied = get_kb_item('Antivirus/SAVCE/hotfix_applied');

if (isnull(edition)) edition = '';
else if (edition == 'sepsb') app += ' Small Business Edition';


if (display_ver =~ "^12\.1\.")
{
  # If host is < 12.1.6 MP5, recommend update to 12.1.6 MP5 + hofix
  if (ver_compare(ver:display_ver, fix:'12.1.7004.6500') == -1)
    fix = '12.1.7004.6500 with hotfix / 12.1.7061.6600';

  # If host is 12.1.6 MP5 < 12.1.6 MP6, check for hotfix (vendor does not specify
  # a value to check, only claims that the existence is proof of patch)
  else if
  (
    ver_compare(ver:display_ver, fix:'12.1.7004.6500') >= 0 &&
    ver_compare(ver:display_ver, fix:'12.1.7061.6600') == -1
  )
  {
    if (isnull(hotfix_applied))
      fix = 'Apply hotfix or upgrade to 12.1.7061.6600';
  }
}

if (!isnull(fix))
{
  port = kb_smb_transport();

  report =
    '\n  Product           : ' + app +
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72542);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_cve_id("CVE-2013-5014", "CVE-2013-5015");
  script_bugtraq_id(65466, 65467);
  script_osvdb_id(103305, 103306);
  script_xref(name:"EDB-ID", value:"31853");

  script_name(english:"Symantec Endpoint Protection Manager < 11.0 RU7-MP4a / 12.1 RU4a Multiple Vulnerabilities (SYM14-004)");
  script_summary(english:"Checks SEPM version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Symantec Endpoint Protection Manager installed on the
remote host is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Symantec Endpoint Protection Manager (SEPM) running on
the remote host is either 11.x prior to 11.0 RU7-MP4a or 12.x prior to
12.1 RU4a.  It is, therefore, affected by multiple vulnerabilities:

  - SEPM is affected by an XML external entity injection
    vulnerability due to a failure to properly sanitize
    user-supplied input. A remote, unauthenticated attacker
    could potentially exploit this vulnerability to read
    arbitrary files. (CVE-2013-5014)

  - SEPM is affected by a SQL injection vulnerability due to
    a failure to properly sanitize user-supplied input. A
    locally authenticated user could potentially exploit
    this vulnerability to execute arbitrary SQL commands
    against the back-end database. (CVE-2013-5015)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/531128/30/0/threaded");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20140213_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9eabd91f");
  script_set_attribute(attribute:"solution", value:"Upgrade to 11.0 RU7-MP4a / 12.1 RU4a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Symantec Endpoint Protection Manager /servlet/ConsoleServlet Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_endpoint_prot_mgr_installed.nasl");
  script_require_keys("SMB/sep_manager/path", "SMB/sep_manager/ver");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

display_ver = get_kb_item_or_exit('SMB/sep_manager/ver');
path = get_kb_item_or_exit('SMB/sep_manager/path');

major_ver = split(display_ver, sep:'.', keep:FALSE);
major_ver = int(major_ver[0]);

fixed_ver = make_array(
  11, '11.0.7405.1424',
  12, '12.1.4023.4080'
);

if (ver_compare(ver:display_ver, fix:fixed_ver[major_ver], strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/SQLInjection', value:TRUE);

  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : '+ path +
      '\n  Installed version : '+ display_ver +
      '\n  Fixed version     : '+ fixed_ver[major_ver] +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Symantec Endpoint Protection Manager', display_ver, path);

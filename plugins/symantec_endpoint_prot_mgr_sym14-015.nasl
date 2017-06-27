#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79083);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_cve_id("CVE-2014-3437", "CVE-2014-3438", "CVE-2014-3439");
  script_bugtraq_id(70843, 70844, 70845);
  script_osvdb_id(114274, 114275, 114276);
  script_xref(name:"EDB-ID", value:"35181");

  script_name(english:"Symantec Endpoint Protection Manager < 12.1 RU5 Multiple Vulnerabilities (SYM14-015)");
  script_summary(english:"Checks the SEPM version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Symantec Endpoint Protection Manager installed on the
remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection Manager (SEPM) installed
on the remote host is 12.1 prior to 12.1 RU5. It is, therefore,
affected by the following vulnerabilities :

  - An XML external entity (XXE) injection vulnerability due
    to improper validation of XML external entities. A
    remote attacker, impersonating the input source of
    external information or updates, can access restricted
    data or leverage additional management console
    functionality using specially crafted XML data.
    (CVE-2014-3437)

  - A reflected cross-site scripting vulnerability due to
    improper validation of user-supplied input to the
    'ErrorMsg' parameter in 'SSO-Error.jsp'. This allows a
    remote attacker, with a specially crafted request, to
    execute arbitrary script code within the browser /
    server trust relationship. (CVE-2014-3438)

  - An arbitrary file write vulnerability in the
    'ConsoleServlet' due to improper filtering of
    user-supplied data to the logging component. This allows
    a remote attacker to write arbitrary code to the log
    file or disk, potentially causing a denial of
    service or unauthorized elevated access.
    (CVE-2014-3439)");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20141105_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a717919b");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec Endpoint Protection Manager 12.1.5 (RU5) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/10");

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

if (display_ver !~ "^12\.") audit(AUDIT_INST_PATH_NOT_VULN, 'Symantec Endpoint Protection Manager', display_ver, path);

fixed_ver = '12.1.5337.5000';

if (ver_compare(ver:display_ver, fix:fixed_ver, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : '+ path +
      '\n  Installed version : '+ display_ver +
      '\n  Fixed version     : '+ fixed_ver +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Symantec Endpoint Protection Manager', display_ver, path);

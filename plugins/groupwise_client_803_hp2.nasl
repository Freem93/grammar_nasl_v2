#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(64471);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/11 20:19:26 $");

  script_cve_id("CVE-2012-0439", "CVE-2013-0804");
  script_bugtraq_id(57657, 57658);
  script_osvdb_id(89699, 89700);
  script_xref(name:"EDB-ID", value:"24490");

  script_name(english:"Novell GroupWise Client 8.x < 8.0.3 Hot Patch 2 / 2012.x < 2012 SP1 Hot Patch 1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of grpwise.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an email application that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Novell GroupWise Client installed on the remote Windows
host is 8.x prior to 8.0.3 Hot Patch 2 (8.0.3.26516) or 2012.x prior to
2012 SP1 Hot Patch 1 (12.0.1.16521).  It is, therefore, reportedly
affected by the following vulnerabilities :

  - An unspecified error exists related to an ActiveX
    control that could allow arbitrary code execution.
    (CVE-2012-0439)

  - Multiple pointer dereference errors exist that could
    allow arbitrary code execution. (CVE-2013-0804)");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-008/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526169/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7011687");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7011688");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Novell GroupWise Client 8.0.3 Hot Patch 2 (8.0.3.26516) /
2012 SP1 Hot Patch 1 (12.0.1.16521) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Novell GroupWise Client gwcls1.dll ActiveX Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("groupwise_client_installed.nasl");
  script_require_keys("SMB/Novell GroupWise Client/Path", "SMB/Novell GroupWise Client/Version");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

version = get_kb_item_or_exit('SMB/Novell GroupWise Client/Version');
path = get_kb_item_or_exit('SMB/Novell GroupWise Client/Path');

if (version =~ '^8\\.' && ver_compare(ver:version, fix:'8.0.3.26516') == -1)
  fixed_version = '8.0.3 Hot Patch 2 (8.0.3.26516)';
else if (version =~ '^12\\.' && ver_compare(ver:version, fix:'12.0.1.16521') == -1)
  fixed_version = '2012 SP1 Hot Patch 1 (12.0.1.16521)';

if (fixed_version)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Novell GroupWise Client', version, path);

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44959);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2009-1430");
  script_bugtraq_id(34672, 34674);
  script_osvdb_id(54158, 54159);
  script_xref(name:"Secunia", value:"34856");
  script_xref(name:"IAVA", value:"2009-A-0037");
  script_xref(name:"ZDI", value:"ZDI-09-018");

  script_name(english:"Symantec Alert Management System 2 RCE (SYM09-007)");
  script_summary(english:"Checks version number of iao.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a service that is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"Alert Management System 2 (AMS2), an optional component included with
multiple Symantec products, is installed on the remote Windows host.
Versions prior to build 150 are affected by multiple stack-based
buffer overflow conditions. A remote attacker can exploit these issues
to crash the service or execute arbitrary code as SYSTEM.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-018/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/503080/100/0/threaded");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2009&suid=20090428_02
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33c06995");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant upgrade referenced in the Symantec advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Symantec Alert Management System Intel Alert Originator Service Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date",value:"2009/04/28");
  script_set_attribute(attribute:"patch_publication_date",value:"2009/04/28");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:system_center");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:antivirus");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:antivirus_central_quarantine_server");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:client_security");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:endpoint_protection");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/svcs");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

if (report_paranoia < 2)
{
  status = get_kb_item("SMB/svc/Intel Alert Originator");
  if (isnull(status))
    exit(0, "The 'SMB/svc/Intel Alert Originator' KB item is missing.");

  if (status != SERVICE_ACTIVE)
    exit(0, "The Alert Originator service is installed but not active.");
}

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

if (
  hotfix_is_vulnerable(file:"iao.exe", version:"6.12.0.150", dir:"\system32\ams_ii")
)
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

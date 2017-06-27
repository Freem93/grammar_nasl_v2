#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51813);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2010-0110", "CVE-2010-0111", "CVE-2010-3268", "CVE-2011-0688");
  script_bugtraq_id(41959, 45935, 45936);
  script_osvdb_id(66807, 70002, 72623, 72624, 72625, 72626, 75041);
  script_xref(name:"EDB-ID", value:"17700");
  script_xref(name:"IAVA", value:"2011-A-0011");
  script_xref(name:"Secunia", value:"43099");

  script_name(english:"Symantec Alert Management System 2 Multiple Vulnerabilities (SYM11-002, SYM11-003)");
  script_summary(english:"Checks version number of iao.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a service that is affected by multiple
remote buffer overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Alert Management System 2 (AMS2), an optional component included with
multiple Symantec products, is installed on the remote host.  Versions
before build 156 are affected by multiple stack-based buffer overflow
vulnerabilities. 

A remote attacker could exploit these issues to crash the service or
to execute arbitrary code as SYSTEM."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://telussecuritylabs.com/threats/show/FSC20100727-01"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://telussecuritylabs.com/threats/show/FSC20101213-06"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-11-028/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-11-029/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-11-030/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-11-031/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-11-032/"
  );
  # http://www.coresecurity.com/content/symantec-intel-handler-service-remote-dos"
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e058ea4d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2010/Dec/261"
  );
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&suid=20110126_00
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d322f62d"
  );
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&suid=20110126_01
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2281a594"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant upgrade referenced in the Symantec advisory
or disable AMS2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Symantec System Center Alert Management System (hndlrsvc.exe) Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/28");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:antivirus");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");


if (report_paranoia < 2)
{
  status = get_kb_item_or_exit("SMB/svc/Intel Alert Originator");

  if (status != SERVICE_ACTIVE)
    exit(0, "The Alert Originator service is installed but not active.");
}

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

if (
  hotfix_is_vulnerable(file:"iao.exe", version:"6.12.0.156", dir:"\system32\ams_ii")
)
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}

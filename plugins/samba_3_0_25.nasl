#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25217);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id("CVE-2007-2444", "CVE-2007-2446", "CVE-2007-2447");
  script_bugtraq_id(23972, 23973, 23974, 24195, 24196, 24197, 24198);
  script_osvdb_id(34698, 34699, 34700, 34731, 34732, 34733);

  script_name(english:"Samba < 3.0.25 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:"The remote Samba server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Samba server installed on
the remote host is affected by multiple buffer overflow and remote
command injection vulnerabilities, which can be exploited remotely, as
well as a local privilege escalation bug.");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2007-2444.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2007-2446.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2007-2447.html" );
  script_set_attribute(attribute:"solution", value:"Upgrade to Samba version 3.0.25 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba "username map script" Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("Settings/ParanoidReport", "SMB/NativeLanManager");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);


lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
  if (ereg(pattern:"Samba 3\.0\.([0-9]|1[0-9]|2[0-4]|25(pre|rc))[^0-9]*$", string:lanman, icase:TRUE))
    security_hole(get_kb_item("SMB/transport"));
}

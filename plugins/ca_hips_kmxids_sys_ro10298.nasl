#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40621);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2009-2740");
  script_bugtraq_id(36078);
  script_osvdb_id(57168);

  script_name(english:"CA Host-Based Intrusion Prevention System Client kmxIds.sys DoS (CA20090818)");
  script_summary(english:"Checks version of kmxIds.sys.");

  script_set_attribute(attribute:"synopsis", value:
"A driver installed on the remote Windows host is affected by a denial
of service vulnerability.");
  script_set_attribute( attribute:"description",  value:
"The remote Windows host contains a version of the 'kmxIds.sys' driver,
a component of CA Host-Based Intrusion Prevention System Client, that
does not correctly handle certain malformed network packets. A remote
attacker can exploit this issue to cause a kernel crash.");
# https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID=214665
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c95182f");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2009/Aug/150");
  script_set_attribute( attribute:"solution",  value:
"Upgrade as necessary to CA Host-Based Intrusion Prevention System 8.1,
install Cumulative Fix 1 RO10298 or later on the CA HIPS server, and
ensure that an updated client installation image is installed on each
client.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

if (hotfix_check_fversion(file:"\System32\drivers\kmxIds.sys", version:"7.3.1.18") == HCF_OLDER)
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

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(34432);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/23 20:42:25 $");

  script_cve_id("CVE-2008-4589");
  script_bugtraq_id(31737);
  script_osvdb_id(49122);

  script_name(english:"Lenovo Rescue and Recovery tvtumon.sys Filename Handling Local Overflow");
  script_summary(english:"Determines the version of Lenovo Rescue and Recovery driver.");
 
  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by an elevation
of privilege vulnerability." );
  script_set_attribute(attribute:"description", value:
"The version of Lenovo Rescue and Recovery monitor driver running on
the remote host is affected by a heap overflow condition. A local
attacker may exploit this to elevate privileges to SYSTEM level.");
  # https://web.archive.org/web/20090426211611/http://www-307.ibm.com/pc/support/site.wss/MIGR-70699.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50bb4c8d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Lenovo Rescue and Recovery version 4.21 or later." );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/16");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

#
include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

if (!is_accessible_share()) exit(0);

if ( hotfix_check_fversion(file:"\system32\drivers\tvtumon.sys", version:"4.20.403.0") == HCF_OLDER )
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

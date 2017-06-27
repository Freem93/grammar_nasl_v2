#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18592);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/09 21:04:55 $");

  script_cve_id("CVE-2005-3168");
  script_bugtraq_id(14093);
  script_osvdb_id(19995);
 
  script_name(english:"Microsoft Windows 2000 SP4 Update Rollup 1 Missing");
  script_summary(english:"Determines whether the URP1 is installed.");
 
  script_set_attribute(attribute:"synopsis", value:
"A security update is missing on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing the Update Rollup 1 (URP1) for Windows
2000 SP4. This update rollup contains several security fixes in
addition to previously released security patches.");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/891861/");
  script_set_attribute(attribute:"solution", value:
"Apply Update Rollup 1 for Windows 2000 SP4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_func.inc");
include("misc_func.inc");

if ( hotfix_check_sp(win2k:5) <= 0 ) exit(0);

if (is_accessible_share ())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"eventlog.dll", version:"5.0.2195.7036", dir:"\system32") )
   security_warning(get_kb_item("SMB/transport"));
 hotfix_check_fversion_end(); 
}
else if ( hotfix_missing(name:"Update Rollup 1") > 0 ) 
   security_warning(get_kb_item("SMB/transport"));

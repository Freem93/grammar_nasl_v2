#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17607);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/09 20:54:59 $");

  script_cve_id("CVE-2005-0904");
  script_bugtraq_id(12889);
  script_osvdb_id(15011);

  script_name(english:"Non-administrators can shut down Windows XP SP1 thru TSShutdn.exe (889323)");
  script_summary(english:"Checks the remote registry for KB889323.");
 
  script_set_attribute(attribute:"synopsis", value:
"It is possible to shutdown the remote host.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Windows XP SP1 on the remote host is missing
security update KB889323. A non-administrative user can remotely shut
down the remote host by using the TSShutdn.exe command.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/889323");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

# Only XP SP1 affected
if ( hotfix_check_sp(xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Termsrv.dll", version:"5.1.2600.1646", dir:"\system32") )
   security_warning(get_kb_item("SMB/transport"));
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"889323") > 0 )
	security_warning(get_kb_item("SMB/transport"));

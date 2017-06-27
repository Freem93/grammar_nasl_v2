#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18119);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2005-1088");
  script_bugtraq_id(13023);
  script_osvdb_id(18732);

  script_name(english:"DameWare Mini Remote Control Server Unspecified Local Privilege Escalation");
  script_summary(english:"Checks for unspecified privilege escalation vulnerability in DameWare Mini Remote Control Server");
 
  script_set_attribute(attribute:"synopsis", value:"A local user can elevate his privileges.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the DameWare Mini Remote Control
program on the remote host may allow an authenticated user with
non-administrator rights to elevate his rights on a remote machine.");
  # http://web.archive.org/web/20050412003302/http://www.dameware.com/support/security/bulletin.asp?ID=SB5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60814edd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to DameWare Mini Remote Control version 3.80 if using 3.x or
to 4.9 if using 4.x." );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dameware:mini_remote_control");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for the version of DameWare Mini RC installed.
key1 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{F275C4B9-0769-4BE9-BDDE-C40A0789623C}/DisplayName";
key2 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{F275C4B9-0769-4BE9-BDDE-C40A0789623C}/DisplayVersion";
if (get_kb_item(key1))
{
  ver = get_kb_item(key2);
  # nb: DameWare's bulletin says the problem is fixed with 3.80 as well as
  #     4.9 so we'll alert on anything less.
  if (ver && ver =~ "^([0-2]|3\.[0-7]|4\.[0-8])") security_hole(get_kb_item("SMB/transport"));
}

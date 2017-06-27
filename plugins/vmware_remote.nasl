#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20729);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/02/10 00:48:53 $");

  script_cve_id("CVE-2005-4459");
  script_bugtraq_id(15998);
  script_osvdb_id(22006);

  script_name(english:"VMware vmnat.exe/vmnet-natd Multiple FTP Command Remote Overflow");
  script_summary(english:"Checks for VMware version");

  script_set_attribute(attribute:"synopsis", value:"It is possible to execute code on the remote system.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the VMware program on the remote host
may allow an attacker to execute code on the system hosting the VMware
instance. 

The vulnerability can be exploited by sending specially crafted FTP PORT
and EPRT requests. 

To be exploitable, the VMware system must be configured to use NAT
networking.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/kb/enduser/std_adp.php?p_faqid=2000");
  script_set_attribute(attribute:"solution", value:
"Upgrade to :

- VMware Workstation 5.5.1 or higher
- VMware Workstation 4.5.2 or higher
- VMware Player 1.0.1 or higher
- VMware GSX Server 3.2.1 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_player");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_workstation");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:gsx_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("smb_func.inc");
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

# VMware Workstation

key1 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{98D1A713-438C-4A23-8AB6-41B37C4A2D47}/DisplayName";
key2 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{98D1A713-438C-4A23-8AB6-41B37C4A2D47}/DisplayVersion";

name = get_kb_item (key1);
version = get_kb_item (key2);

if (!isnull (name) && (name == "VMware Workstation") )
{
 version = split (version, sep:".", keep:FALSE);

 version[0] = int(version[0]);
 version[1] = int(version[1]);
 version[2] = int(version[2]);

 if ( (version[0] < 4) ||
      ( (version[0] == 4) && (version[1] < 5) ) ||
      ( (version[0] == 4) && (version[1] == 5) && (version[2] < 3) ) ||
      ( (version[0] == 5) && (version[1] < 5) ) ||
      ( (version[0] == 5) && (version[1] == 5) && (version[2] < 1) ) )
 {
  security_hole(port);
  exit (0);
 }
}


# VMware GSX Server

key1 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{5B9605EF-01FA-4429-8174-5A1039B0A7A5}/DisplayName";
key2 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{5B9605EF-01FA-4429-8174-5A1039B0A7A5}/DisplayVersion";

name = get_kb_item (key1);
version = get_kb_item (key2);

if (!isnull (name) && ("VMware GSX Server" >< name) )
{
 version = split (version, sep:".", keep:FALSE);

 version[0] = int(version[0]);
 version[1] = int(version[1]);
 version[2] = int(version[2]);

 if ( (version[0] < 3) ||
      ( (version[0] == 3) && (version[1] < 2) ) ||
      ( (version[0] == 3) && (version[1] == 2) && (version[2] < 1) ) )
 {
  security_hole(port);
  exit (0);
 }
}


# VMware Player

key1 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{31799B14-B3E7-4522-B393-6206C03EC5D3}/DisplayName";
key2 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{31799B14-B3E7-4522-B393-6206C03EC5D3}/DisplayVersion";

name = get_kb_item (key1);
version = get_kb_item (key2);

if (!isnull (name) && ("VMware Player" >< name) )
{
 version = split (version, sep:".", keep:FALSE);

 version[0] = int(version[0]);
 version[1] = int(version[1]);
 version[2] = int(version[2]);

 if ( (version[0] < 1) ||
      ( (version[0] == 1) && (version[1] == 0) && (version[2] < 1) ) )
 {
  security_hole(port);
  exit (0);
 }
}

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14726);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2004-2713");
 script_osvdb_id(9761);

 script_name(english:"ZoneAlarm Pro Configuration File/Directory Permission Weakness DoS");

 script_set_attribute(attribute:"synopsis", value:
"This host is running a firewall with a denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"This host is running a version of ZoneAlarm Pro that contains a flaw which may
allow a local denial of service. To exploit this flaw, an attacker would need
to tamper with the files located in %windir%/Internet Logs. An attacker may
modify them and prevent ZoneAlarm from starting up properly." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Aug/911");
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
 script_cwe_id(264);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/20");
 script_cvs_date("$Date: 2016/11/01 20:05:52 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
 script_summary(english:"Check ZoneAlarm Pro version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/ZoneAlarm Pro/DisplayName";
key2 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/ZoneAlarm Pro/DisplayVersion";

if (get_kb_item (key))
{
 version = get_kb_item (key2);
 if (version)
 {
  set_kb_item (name:"zonealarm/version", value:version);

  if(ereg(pattern:"[1-4]\.|5\.0\.|5\.1\.", string:version))
  {
   security_warning(0);
  }
 }
}

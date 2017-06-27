#
# Script Written By Ferdy Riphagen 
# Script distributed under the GNU GPLv2 License. 
#


include("compat.inc");

if (description) {
 script_id(25550);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2006-2679");
 script_bugtraq_id(18094);
 script_xref(name:"OSVDB", value:"25888");

 script_name(english:"Cisco VPN Client Dialer Local Privilege Escalation");

 script_set_attribute(attribute:"synopsis", value:
"The remote windows host contains an application that is affected by a
privilege escalation vulnerability." );
 script_set_attribute(attribute:"description", value:
"The installed Cisco VPN Client version is prone to a privilege
escalation attack.  By using the 'Start before logon' feature in the
VPN client dialer, a local attacker may gain privileges and execute
arbitrary commands with SYSTEM privileges." );
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20060524-vpnclient
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc07e815" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.8.01.0300 or a later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/24");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/05/24");
 script_cvs_date("$Date: 2013/03/26 21:38:04 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:vpn_client");
script_end_attributes();

 summary = "Detects a privilege escalation in the Cisco VPN Client by query its version number";
 script_summary(english:summary);
 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2007-2013 Ferdy Riphagen");

 script_dependencies("cisco_vpn_client_detect.nasl");
 script_require_keys("SMB/CiscoVPNClient/Version");
 exit(0);
}

version = get_kb_item("SMB/CiscoVPNClient/Version");
if (version) {
	# These versions are reported vulnerable:
	# - 2.x, 3.x, 4.0.x, 4.6.x, 4.7.x, 4.8.00.x
	# Not vulnerable:
	# - 4.7.00.0533
 	if ("4.7.00.0533" >< version) exit(0);
	if (egrep(pattern:"^([23]\.|4\.([067]\.|8\.00)).+", string:version)) {
		security_warning(port:get_kb_item("SMB/transport"));
	}
}

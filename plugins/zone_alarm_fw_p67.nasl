#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14660);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2000-0339");  
 script_bugtraq_id(1137);
 script_osvdb_id(1294);

 script_name(english:"ZoneAlarm Personal Firewall UDP Source Port 67 Bypass");

 script_set_attribute(attribute:"synopsis", value:
"This host is running a firewall that fails to filter certain types of
traffic." );
 script_set_attribute(attribute:"description", value:
"This version of ZoneAlarm contains a flaw that may allow a remote
attacker to bypass the ruleset.  The issue is due to ZoneAlarm not
monitoring and alerting UDP traffic with a source port of 67. 

This allows an attacker to bypass the firewall to reach protected
hosts without setting off warnings on the firewall." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Apr/134");
 script_set_attribute(attribute:"solution", value:
"Upgrade at least to version 2.1.25." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/04/20");
 script_cvs_date("$Date: 2016/11/01 20:05:52 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
 script_summary(english:"Check ZoneAlarm version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");
 script_dependencies("netbios_name_get.nasl","zone_alarm_local_dos.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/transport", "zonealarm/version");

 script_require_ports(139, 445);
 exit(0);
}

zaversion = get_kb_item ("zonealarm/version");
if (!zaversion) exit (0);

if(ereg(pattern:"^([0-1]\.|2\.0|2\.1\.([0-9]|1[0-9]|2[0-4])[^0-9])", string:zaversion))
{
 security_warning(0);
}

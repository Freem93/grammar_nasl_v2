#
# This script was written by Joseph Mlodzianowski <joseph@rapter.net>
# 
# 


include("compat.inc");

if(description)
{
 script_id(11880);
 script_version ("$Revision: 1.14 $");
 script_cvs_date("$Date: 2013/01/25 01:19:08 $");
# script_cve_id("CVE-2003-00002");
 name["english"] = "Fluxay Sensor Detection";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host may have been compromised." );
 script_set_attribute(attribute:"description", value:
"This host appears to be running Fluxay Sensor on this port. 

Fluxay Sensor is a backdoor that allows an intruder to gain remote
access to files on your computer.  Similar to SubSeven, this program
installs as a service and is password protected to make it difficult
to stop or remove it. 

An attacker may use this backdoor to steal passwords from the remote
host or use it in other attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10e4148e" );
 script_set_attribute(attribute:"solution", value:
"Refer to the link referenced above for information on detection and
removal." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/10/13");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Determines the presence of Fluxay Sensor";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2003-2013 J.Mlodzianowski");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("find_service2.nasl");
 script_require_keys("Services/fluxay");
 exit(0);
}


#
# The code starts here:
#

port = get_kb_item("Services/fluxay");
if ( port ) security_hole(port);

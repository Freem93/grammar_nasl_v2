#
# This script was written by Joseph Mlodzianowski <joseph@rapter.net>
# 
# 


include("compat.inc");

if(description)
{

 script_id(11881);
 script_version ("$Revision: 1.14 $");
 script_cvs_date("$Date: 2013/01/25 01:19:08 $");
# script_cve_id("CVE-2003-00002");
 name["english"] = "Wollf Backdoor Detection";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"This host appears to be running Wollf on this port. Wollf Can be used as
a Backdoor which allows an intruder gain remote access to files on your 
computer. 
If you did not install this program for remote management then this host
may be compromised.

An attacker may use it to steal your passwords, or redirect ports on 
your system to launch other attacks" );
 script_set_attribute(attribute:"solution", value:
"See http://www.nessus.org/u?10e4148e for details on removal." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/10/13");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Determines the presence of Wollf";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2003-2013 J.Mlodzianowski");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("find_service2.nasl");
 script_require_keys("Services/wollf");
 exit(0);
}


#
# The code starts here:
#

port = get_kb_item("Services/wollf");
if ( port ) security_hole(port);


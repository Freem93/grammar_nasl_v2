#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(24733);
 script_version("$Revision: 1.16 $");
 script_cve_id("CVE-2007-1005");
 script_bugtraq_id(22743);
 script_osvdb_id(32290);

 script_name(english:"CA eTrust Intrusion Detection System Key Exchange Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote IDS service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running CA eTrust Intrusion Detection System, a
security solution with intrusion detection, antivirus, web filtering
and session monitoring. 

The remote version of this software is affected by a denial of service
vulnerability in the way it handles session keys.  An attacker can
exploit this issue to crash the remote service by sending a specially
crafted administration packet." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.0.0.41, 3.0.2.07 or 3.0.5.80." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"see_also", value:"http://supportconnectw.ca.com/public/ca_common_docs/eid_secnotice.asp" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/27");
 script_cvs_date("$Date: 2016/11/11 20:08:42 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines if eTrust Intrusion Detection System is vulnerable to a Denial of Service");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("etrust_ids.nasl");
 script_require_keys("eTrust/intrusion_detection_system");
 exit(0);
}

vers = get_kb_item ("eTrust/intrusion_detection_system");
if (!vers) exit(0);

vers = split (vers, sep:".", keep:0);

if ( (int(vers[0]) < 2) ||
     ( (int(vers[0]) == 2) && (int(vers[1]) == 0) && (int(vers[2]) < 41) ) ||
     ( (int(vers[0]) == 3) && (int(vers[1]) == 0) && (int(vers[2]) < 207) ) ||
     ( (int(vers[0]) == 3) && (int(vers[1]) == 0) && (int(vers[2]) > 500) && (int(vers[2]) < 580) ) )
  security_hole(get_kb_item("Services/eTrust-IDS"));

#
# (C) Tenable Network Security, Inc.
#


# This script depends on a .nbin plugin
if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if (description)
{
 script_id(21209);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/12/14 20:22:12 $");

 script_cve_id("CVE-2005-3265", "CVE-2005-3267");
 script_bugtraq_id(15190, 15192);
 script_osvdb_id(20306, 20307, 20308);

 script_name(english:"Skype < 1.4.0.84 Multiple Vulnerabilities (uncredentialed check)");
 script_summary(english:"Checks for Skype Heap overflow for Windows");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Skype, a peer-to-peer voice over IP
software. 

The remote version of this software is vulnerable to a heap overflow
in the handling of its data structures.  An attacker can exploit this
flaw by sending a specially crafted network packet to UDP or TCP ports
Skype is listening on. A successful exploitation of this flaw will 
result in code execution on the remote host. 

In addition, Skype has been reported to contain overflows in the
handling of VCards and callto/skype URLs. However, Nessus has not
checked for them." );
 script_set_attribute(attribute:"see_also", value:"http://www.skype.com/security/skype-sb-2005-03.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to skype version 1.4.0.84 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119, 189);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/10/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

 script_dependencies("skype_version.nbin");
 script_require_keys("Services/skype");

 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc:"skype", exit_on_fail:TRUE);

ts = get_kb_item_or_exit("Skype/"+port+"/stackTimeStamp");
if (ts > 0 && ts < 510211313) security_hole(port);
else exit(0, "The Skype client listening on port "+port+" is not affected based on its timestamp ("+ts+").");

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11396);
 script_version("$Revision: 1.13 $");
 script_bugtraq_id(7070);
 script_osvdb_id(57590, 57591);

 script_name(english:"HP JetDirect < Q.24.09 Multiple Vulnerabilities");
 script_summary(english:"Uses SNMP to determine if a flaw is present");

 script_set_attribute(attribute:"synopsis", value:
"The remote print server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote HP JetDirect is, according to its version number,
vulnerable to an issue that may allow an attacker to
gain unauthorized access on this printer, or crash it." );
 # http://web.archive.org/web/20031118235728/http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00001902
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec454809" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firmware Q.24.09 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/15");
 script_set_attribute(attribute:"patch_publication_date", value: "2003/03/11");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:jetdirect");
script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("snmp_sysDesc.nasl");
 script_require_keys("SNMP/community", "SNMP/sysDesc");
 exit(0);
}



os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
if(egrep(pattern:"JETDIRECT.*Q\.24\.06", string:os, icase:TRUE))
  	security_warning(0);



#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(16260);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2012/12/10 03:02:35 $");

 script_cve_id("CVE-2005-0033");
 script_bugtraq_id(12364);
 script_osvdb_id(13176);
 script_xref(name:"CERT", value:"327633");
 
 script_name(english:"ISC BIND < 8.4.6 q_usedns Array Remote Overflow DoS");
 script_summary(english:"Checks the remote BIND version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote name server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote bind server, according to its version number, has a buffer
overflow involving the 'q_usedns' buffer.  An attacker may be able to
leverage this issue to crash the affected service." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to bind 8.4.6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/25");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}

vers = string(get_kb_item("bind/version"));
if(!vers)exit(0);

if (ereg(string:vers, pattern:"^8\.4\.[4-5]$") )
  security_warning(53);

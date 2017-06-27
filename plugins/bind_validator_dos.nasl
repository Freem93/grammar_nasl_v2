#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(16261);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2017/05/02 23:36:52 $");

 script_cve_id("CVE-2005-0034");
 script_bugtraq_id(12365, 12497);
 script_osvdb_id(13175);
 script_xref(name:"CERT", value:"938617");
 
 script_name(english:"ISC BIND < 9.3.1 Validator Self Checking Remote DoS");
 script_summary(english:"Checks the remote BIND version");

 script_set_attribute(attribute:"synopsis", value:
"The remote name server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote BIND server, according to its version number, has a flaw in
the way 'authvalidator()' is implemented. 

Provided DNSSEC has been enabled in the remote name server, an
attacker may be able to launch a denial of service attack against the
remote service." );
 # https://kb.isc.org/article/AA-00958/0/CVE-2005-0034%3A-BIND%3A-Self-check-failing.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cde0d404");
 script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 9.3.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/25");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}

include('global_settings.inc');

if (report_paranoia < 1) exit(0);	# FP on Mandrake

vers = string(get_kb_item("bind/version"));
if(!vers)exit(0);

if (ereg(string:vers, pattern:"^9\.3\.0$"))
  security_warning(port: 53, proto: 'udp');

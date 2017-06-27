#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11857);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2012/06/14 20:11:56 $");

 script_cve_id("CVE-2002-0029");
 script_bugtraq_id(6186);
 script_osvdb_id(8330);
 
 script_name(english:"ISC BIND < 4.9.11 stub resolver (libresolv.a) DNS Response Overflow");
 script_summary(english:"Checks that BIND is not version 4.9.2 through 4.9.10");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to use the remote name server to execute arbitrary code on
the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote BIND 4.x server, according to its version number, is vulnerable 
to a buffer overflow in the DNS stub resolver library.

An attacker might use this flaw to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 4.9.11 or later in the 4.x branch, or consider upgrading 
to a more recent release." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/09/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/11/12");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2012 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}

vers = get_kb_item("bind/version");
if(!vers)exit(0);
if (vers =~ "^4\.9\.[2-9]") security_hole(53); 
if (vers =~ "^4\.9\.10") security_hole(53);



#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Ian Koenig <ian@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID and CVE
#      Updated to handle two specific types of attacks instead of just a general
#        statement of "vulnerable to DNS storm attacks".
#      


include("compat.inc");

if (description)
{
 script_id(10886);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2016/11/11 20:08:42 $");

 script_cve_id("CVE-2002-1219", "CVE-2002-1220", "CVE-2002-1221");
 script_bugtraq_id(6159, 6160, 6161);
 script_osvdb_id(869, 9724, 9725);
 script_xref(name:"SuSE", value:"SUSE-SA:2002:044");
 
 script_name(english:"ISC BIND < 8.3.4 Multiple Remote Vulnerabilities");
 script_summary(english:"Checks the remote BIND version");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to use the remote name server to break into the
remote host.");
 script_set_attribute(attribute:"description", value:
"The remote name server, according to its version number, is affected
by the following vulnerabilities :

- When running the recursive DNS functionality, this server is
vulnerable to a buffer overflow attack that may let an attacker
execute arbitrary code on the remote host. 

- It is vulnerable to a denial of service attack (crash) via SIG RR
elements with invalid expiry times. 

- It is vulnerable to a denial of service attack when a DNS lookup is
requested on a nonexistent sub-domain of a valid domain and an OPT
resource record with a large UDP payload is attached, the server may
fail.");
 script_set_attribute(attribute:"solution", value:"Upgrade to BIND 8.3.4 or newer");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/03/08");
 script_set_attribute(attribute:"vuln_publication_date", value:"2002/11/12");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english: "DNS");

 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}

vers = get_kb_item("bind/version");
if(!vers)exit(0);

if(ereg(string:vers,
	 pattern:"^8\.(([0-1].*)|(2\.[0-6])|(3\.0\.[0-3])).*"))security_hole(53);


#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(18369);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2005-1408");
 script_bugtraq_id(13771);
 script_osvdb_id(16853);

 script_name(english:"Apple Keynote Presentation < 2.0.2 keynote: URI Handler Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that may allow an attacker
to read arbitrary files from the local system." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Keynote 2 which is older than 
2.0.2. The installed version is affected by a security issue which 
may allow an attacker to send a rogue keynote file containing 
malformed URI links in it. An attacker can exploit this issue to read
and upload arbitrary local files to an arbitrary location." );
 # http://web.archive.org/web/20060419012331/http://docs.info.apple.com/article.html?artnum=301713
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99229f60" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Keynote 2.0.2" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/25");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/05/25");
 script_cvs_date("$Date: 2013/03/04 23:24:26 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_summary(english:"Check for Keynote 2.0.2");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

if ( egrep(pattern:"^Keynote 2\.pkg", string:packages) &&
     !egrep(pattern:"^Keynote2\.0\.([2-9]|[1-9][0-9])\.pkg", string:packages) &&
     !egrep(pattern:"^Keynote2\.[1-9]+\.", string:packages) )
		security_hole();

#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(25554);
 script_version ("$Revision: 1.18 $");

 script_cve_id("CVE-2007-2242");
 script_bugtraq_id(23615);
 script_osvdb_id(35303);

 script_name(english:"Mac OS X 10.4.x < 10.4.10 IPv6 Type 0 Route Headers DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4.x that is prior
to 10.4.10. 

This update a security fix for IPv6 type 0 routing headers, which
might be abused by an attacker to consume excessive bandwidth." );
  # http://web.archive.org/web/20071109075543/http://docs.info.apple.com/article.html?artnum=305712
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1a804bf" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.4.10 :

http://docs.info.apple.com/article.html?artnum=305533" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/04/24");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/06/19");
 script_cvs_date("$Date: 2016/05/16 14:02:53 $");
script_set_attribute(attribute:"plugin_type", value:"combined");
script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("os_fingerprint.nasl");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) {
	os = get_kb_item("Host/OS");
	confidence = get_kb_item("Host/OS/Confidence");
	if ( confidence <= 90 ) exit(0);
}
if ( ! os ) exit(0);
if ( ereg(pattern:"Mac OS X 10\.4($|\.[1-9]([^0-9]|$))", string:os)) security_hole(0);

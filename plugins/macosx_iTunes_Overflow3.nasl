#
# (C) Tenable Network Security, Inc.
#


if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(21781);
 script_version ("$Revision: 1.16 $");
 script_cvs_date("$Date: 2013/03/04 23:26:49 $");

 script_cve_id("CVE-2006-1467");
 script_bugtraq_id(18730);
 script_osvdb_id(26909);

 script_name(english:"iTunes < 6.0.5 AAC File Integer Overflow (Mac OS X)");
 script_summary(english:"Check the version of iTunes");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a remote
code execution flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running iTunes, a popular jukebox program. 

The remote version of this software is vulnerable to an integer
overflow when it parses specially crafted AAC files which may lead to
the execution of arbitrary code. 

An attacker may exploit this flaw by sending a malformed AAC file to a
user on the remote host and wait for him to play it with iTunes." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/10781" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to iTunes 6.0.5 or newer" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/29");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/06/23");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("macosx_iTunes_Overflow.nasl");
 script_require_keys("iTunes/Version");
 exit(0);
}


version = get_kb_item("iTunes/Version");
if ( ! version ) exit(0);
if ( egrep(pattern:"^([1-5]\..*|6\.0($|\.[0-4]$))", string:version )) security_warning(0);

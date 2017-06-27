#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(18214);
 script_version ("$Revision: 1.15 $");
 script_cvs_date("$Date: 2013/03/04 23:26:49 $");

 script_cve_id("CVE-2005-1248");
 script_bugtraq_id(13565);
 script_osvdb_id(16243);

 script_name(english:"iTunes < 4.8.0 MPEG-4 Parsing Overflow (Mac OS X)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of iTunes which is older than
version 4.8.0. Such versions reportedly fail to perform certain 
validation checks on MPEG4 files, and hence it could be possible 
to trigger a buffer overflow condition. Successful exploitation of 
this issue could lead to a denial of service condition or arbitrary
code execution on the remote system." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/8545" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to iTunes 4.8.0" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/09");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/05/09");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
 script_end_attributes();

 script_summary(english:"Check the version of iTunes");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("macosx_iTunes_Overflow.nasl");
 script_require_keys("iTunes/Version");
 exit(0);
}


version = get_kb_item("iTunes/Version");
if ( ! version ) exit(0);
if ( egrep(pattern:"^4\.([0-7]\..*)$", string:version )) security_hole(0); 

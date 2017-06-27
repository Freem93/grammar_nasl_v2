#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if (description)
{
  script_id(21554);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2006-1249", "CVE-2006-1453", "CVE-2006-1454", "CVE-2006-1458", "CVE-2006-1459",
                "CVE-2006-1460", "CVE-2006-1461", "CVE-2006-1462", "CVE-2006-1463", "CVE-2006-1464",
                "CVE-2006-1465", "CVE-2006-2238");
  script_bugtraq_id(17074, 17953);
  script_osvdb_id(
    24820,
    25508,
    25509,
    25510,
    25511,
    25512,
    25513,
    25514,
    25515,
    25516,
    25517
  );

  script_name(english:"Quicktime < 7.1 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Quicktime on Mac OS X");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote version of QuickTime is affected by multiple overflow
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Quicktime prior to
7.1. 

The remote version of Quicktime is vulnerable to various integer and
buffer overflows involving specially crafted image and media files. 
An attacker may be able to leverage these issues to execute arbitrary
code on the remote host by sending a malformed file to a victim and
having him open it using QuickTime player." );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2006-May/045979.html" );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2006-May/045981.html" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=303752" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Quicktime version 7.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(189);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/09");
 script_cvs_date("$Date: 2014/08/15 21:51:08 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/05/09");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("macosx_Quicktime652.nasl");
 script_require_keys("MacOSX/QuickTime/Version");
 exit(0);
}

#

ver = get_kb_item("MacOSX/QuickTime/Version");
if ( ! ver ) exit(0);

version = split(ver, sep:'.', keep:FALSE);

if ( int(version[0]) == 7 &&  int(version[1]) == 0 )
		security_hole( 0 );

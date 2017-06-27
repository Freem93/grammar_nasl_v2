#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(12515);
 script_version ("$Revision: 1.14 $");

 script_cve_id("CVE-2003-0975");
 script_bugtraq_id(9065);
 script_osvdb_id(2860);

 script_name(english:"Mac OS X Safari Null Character Cookie Theft (Security Update 2003-12-05)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X security update." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Mac OS X Security Update 2003-12-05. This
update fixes a flaw in the Safari web browser that may allow a rogue 
website to access the web cookies of the user of the remote host." );
 # http://web.archive.org/web/20060405112613/http://docs.info.apple.com/article.html?artnum=61798
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f26343c2" );
 script_set_attribute(attribute:"solution", value:
"Install security update 2003-12-05." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/11/25");
 script_set_attribute(attribute:"patch_publication_date", value: "2002/11/15");
 script_cvs_date("$Date: 2013/03/04 23:24:26 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
script_end_attributes();

 script_summary(english:"Check for Security Update 2003-12-05");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");

# Security Update 2004-05-03 actually includes this update for MacOS X 10.2.8 Client
if ( egrep(pattern:"Darwin.* 6\.8\.", string:uname) )
{
 if ( egrep(pattern:"^SecUpd2004-05-03", string:packages) ) exit(0);
}


# MacOS X 10.2.8 and 10.3.1 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.1\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecurityUpd2003-12-05", string:packages) ) security_warning(0);
}

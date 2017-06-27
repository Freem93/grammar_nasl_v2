#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(12514);
 script_version ("$Revision: 1.15 $");

 script_cve_id("CVE-2003-0913");
 script_bugtraq_id(8979);
 script_osvdb_id(2777);

 script_name(english:"Mac OS X Terminal Application Unspecified Issue (Security Update 2003-11-04)");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X security update." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Mac OS X Security Update 2003-11-04.  This
update fixes a flaw in the Terminal application that may allow a rogue
web site to access the web cookies of the user of the remote host." );
 # http://web.archive.org/web/20071017185459/http://docs.info.apple.com/article.html?artnum=120269
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10588546" );
 script_set_attribute(attribute:"solution", value:
"Install Security Update 2003-11-04." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/11/04");
 script_set_attribute(attribute:"patch_publication_date", value: "2003/11/04");
 script_cvs_date("$Date: 2013/03/04 23:24:26 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
script_end_attributes();

 script_summary(english:"Check for Security Update 2003-11-04");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

#

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");

# MacOS X 10.3.1 only
if ( egrep(pattern:"Darwin.* 7\.1\.", string:uname) )
{
  if ( ! egrep(pattern:"^SecurityUpd2003-11-04", string:packages) ) security_warning(0);
}

#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14768);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2004-0873");
 script_bugtraq_id(11207);
 script_osvdb_id(10007);

 script_name(english:"Mac OS X iChat Link Handling Arbitrary Command Execution (Security Update 2004-09-16)");
 script_summary(english:"Check for Security Update 2004-09-16");
 
 script_set_attribute( attribute:"synopsis",  value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute( attribute:"description",   value:
"The remote host is missing Security Update 2004-09-16.

This security update is for iChat. There is a bug in older versions
of iChat where an attacker may execute commands on the local system
by sending malformed links which will execute local commands to an
iChat user on the remote host." );
 # http://web.archive.org/web/20080915104713/http://support.apple.com/kb/HT1646?
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?210abeb5"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2004-09-16."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/16");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/09/16");
 script_cvs_date("$Date: 2013/03/05 23:04:26 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

#

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# MacOS X 10.2.8, 10.3.4 and 10.3.5 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[45]\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd(Srvr)?2004-09-16", string:packages) ) security_warning(0);
}

#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(12520);
 script_version ("$Revision: 1.19 $");

 script_cve_id("CVE-2004-0538", "CVE-2004-0539");
 script_bugtraq_id(10486);
 script_osvdb_id(8432, 8433);

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2004-06-07)");
 script_summary(english:"Check for Security Update 2004-06-07");
 
 script_set_attribute(
   attribute:"synopsis",
   value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute(
   attribute:"description", 
   value:
"The remote host is missing Security Update 2004-06-07.  This
security update includes fixes for the following components :

  DiskImages
  LaunchServices
  Safari
  Terminal

This update fixes a security problem which may allow an attacker
to execute arbitrary commands the on the remote host by abusing
of a flaw in Safari and the components listed above. To exploit
this flaw, an attacker would need to set up a rogue web site with
malformed HTML links, and lure the user of the remote host into
visiting them." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/HT1646"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2004-06-07."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/06/07");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/05/13");
 script_cvs_date("$Date: 2013/03/05 23:07:11 $");
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
# MacOS X 10.2.x and 10.3.x only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.4\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd2004-06-07", string:packages) ) security_warning(0);
}

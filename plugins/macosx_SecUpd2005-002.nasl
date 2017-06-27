#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17195);
 script_version ("$Revision: 1.15 $");

 script_cve_id("CVE-2004-1029");
 script_bugtraq_id(11726);
 script_osvdb_id(12095);

 script_name(english:"Mac OS X Java JRE Plug-in Capability Arbitrary Package Access (Security Update 2005-002)");
 script_summary(english:"Check for Security Update 2005-002");

 script_set_attribute( attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute( attribute:"description",  value:
"The remote host is missing Security Update 2005-002. This security
update contains a security bugfix for Java 1.4.2.

A vulnerability in the Java Plug-in may allow an untrusted applet to
escalate privileges, through JavaScript calling into Java code,
including reading and writing files with the privileges of the user
running the applet.  Releases prior to Java 1.4.2 on Mac OS X are not
affected by this vulnerability." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/TA22931"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2005-002."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/22");
 script_cvs_date("$Date: 2011/08/08 17:20:26 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/11/22");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# MacOS X 10.2.8, 10.3.7 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[78]\.)", string:uname) )
{
  if ( egrep(pattern:"^Java142\.pkg", string:packages) &&
      !egrep(pattern:"^SecUpd(Srvr)?2005-002", string:packages) ) security_warning(0);
	else non_vuln = 1;
}
else if ( egrep(pattern:"Darwin.* (6\.9|[0-9][0-9]\.|7\.(9\.|[0-9][0-9]\.))", string:uname) ) non_vuln = 1;

if ( non_vuln )
{
 set_kb_item(name:"CVE-2004-1029", value:TRUE);
}

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14251);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2012/10/02 21:45:31 $");

 script_cve_id("CVE-2003-1011");
 script_bugtraq_id(8945);
 script_osvdb_id(7098);
 script_xref(name:"Secunia", value:"10474");
 
 script_name(english:"Apple Mac OS X USB Keyboard Ctrl Key Root Access (Apple SA 2003-12-19)");
 script_summary(english:"Checks for Security Update 2003-12-19");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a local privilege escalation
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is missing Security Update 2003-12-19.

Mac OS X contains a flaw that may allow a malicious user 
with local access to gain root access. 

The issue is triggered when the Ctrl and c keys are pressed 
on the connected USB keyboard during boot and thus interrupting 
the system initialization. 

It is possible that the flaw may allow root access resulting 
in a loss of integrity." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=61798" );
 script_set_attribute(attribute:"solution", value:
"Apply Mac OS X security update 2003-12-19." );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/12/19");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe",value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# MacOS X 10.2.8 and 10.3.2 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.2\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd2003-12-19", string:packages) ) 
  {
	security_hole(0);
  }
  else
  {
  	#all can fixes with this security updates
	#set_kb_item(name:"CVE-2003-1007", value:TRUE);
  	#set_kb_item(name:"CVE-2003-1006", value:TRUE);
  	#set_kb_item(name:"CVE-2003-1009", value:TRUE);
  	#set_kb_item(name:"CVE-2003-0792", value:TRUE);
  	#set_kb_item(name:"CVE-2003-1010", value:TRUE);
  	#set_kb_item(name:"CVE-2003-0962", value:TRUE);
  	#set_kb_item(name:"CVE-2003-1005", value:TRUE);
  	#set_kb_item(name:"CVE-2003-1008", value:TRUE);
	set_kb_item(name:"CVE-2003-1011", value:TRUE);
  }
}

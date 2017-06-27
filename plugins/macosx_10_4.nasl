#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(18352);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2005-1430");
 script_bugtraq_id(13467);
 script_osvdb_id(16254);

 script_name(english:"Mac OS X < 10.4 pty Permission Weakness");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote version of the operating system contains a vulnerability
which has been patched by the vendor in a newer release of the
system" );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X which is older than
version 10.4.

Versions older than 10.4 contain a security issue in the way they handle
the permissions of pseudo terminals. 

When an application uses a new pseudo terminal, it can not restrict its 
permissions to a safe mode. As a result, every created pseudo terminal
has permissions 0666 set, which allows a local attacker to sniff the session
of other users." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.4 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/397306" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/01");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/05/01");
 script_cvs_date("$Date: 2016/11/28 21:06:37 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl", "mdns.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("mDNS/os");
if ( ! os ) exit(0);

if ( ereg(pattern:"Mac OS X 10\.[0-3]([^0-9]|$)", string:os )) security_warning(0);

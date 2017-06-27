#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(18683);
 script_version ("$Revision: 1.21 $");

 script_cve_id("CVE-2005-1333", "CVE-2005-1474", "CVE-2005-2194");
 script_bugtraq_id(14241);
 script_osvdb_id(16074, 16499, 17880);

 script_name(english:"Mac OS X 10.4.x < 10.4.2 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host may be affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4.x that is prior
to 10.4.2. Mac OS X 10.4.2 contains several security fixes for :

- TCP/IP
- Dashboard
- Bluetooth File and Object Exchange" );
  # http://web.archive.org/web/20060419231505/http://docs.info.apple.com/article.html?artnum=301948
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35ecc934" );
 script_set_attribute(attribute:"solution", value:
"Apply the Mac OS X 10.4.2 Update." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/03");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/07/11");
 script_cvs_date("$Date: 2016/04/21 16:08:18 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
script_end_attributes();

 script_summary(english:"Check the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl", "mdns.nasl");
 #script_require_keys("Host/MacOSX/packages");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("mDNS/os");
if ( ! os ) exit(0);

if ( ereg(pattern:"Mac OS X 10\.4($|\.1([^0-9]|$))", string:os )) security_warning(0);

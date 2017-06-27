# @DEPRECATED@
#
# Disabled on 2014/07/06. Deprecated by unsupported_operating_system.nasl.
#

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(12521);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2015/09/24 21:17:12 $");

 script_cve_id("CVE-2004-0743", "CVE-2004-0744", "CVE-2004-0485");
 script_bugtraq_id(10904, 10406, 10401, 10400);

 script_name(english:"MacOS X Version Unsupported");
 script_summary(english:"Check for the version of MacOS X");

 script_set_attribute(attribute:"synopsis", value:"The remote host is using an unsupported version of Mac OS X.");
 script_set_attribute(attribute:"description", value:
"The version of Mac OS X on the remote system is unsupported, and
therefore unable to receive the latest security updates from Apple.");
 script_set_attribute(attribute:"solution", value:"Upgrade to an up-to-date version of Mac OS X.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");

 script_dependencies("os_fingerprint.nasl", "ssh_get_info.nasl");
 script_require_keys("Host/OS");

 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Use plugin #33850 (unsupported_operating_system.nasl) instead.");


#

os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("Host/OS");

if ( ! os ) exit(0, "The 'Host/MacOSX/Version' and 'Host/OS' KB items are missing.");


if ( os && "Mac OS X" >< os )
{
 version = os - "Mac OS X ";

 set_kb_item(name:"Host/MacOSX", value: os);
 if ( ereg(pattern:"Mac OS X 10\.1\.", string:os ))
 {
  report = "
The remote host is running Mac OS X 10.1. This version is not supported
by Apple any more, you should upgrade the remote host to the latest version
of Mac OS X.
";
  if ( ereg(pattern:"Mac OS X 10\.1\.[0-4]", string:os ))
  {
   report += "
In addition to this, the remote host should at least be upgraded to
MacOS 10.1.5 using 'softwareupdate', as it is the last supported version
of the system.
";
  }
  if (defined_func("report_xml_tag"))
  {
    report_xml_tag(tag:"operating-system-unsupported", value:"true");
    report_xml_tag(tag:"UnsupportedProduct:apple:mac_os_x:"+version, value:"true");
  }
  security_hole(port:0, extra:report);
 }

 if ( ereg(pattern:"Mac OS X 10\.2\.", string:os ))
 {
  report = "
The remote host is running Mac OS X 10.2. This version is not supported
by Apple any more, you should upgrade the remote host to the latest version
of Mac OS X.
";
  if ( ereg(pattern:"Mac OS X 10\.2\.[0-7]", string:os ))
  {
   report += "
In addition to this, the remote host should at least be upgraded to
MacOS 10.2.8 using 'softwareupdate', as it is the last supported version
of the system.
";
  }

  if (defined_func("report_xml_tag"))
  {
    report_xml_tag(tag:"operating-system-unsupported", value:"true");
    report_xml_tag(tag:"UnsupportedProduct:apple:mac_os_x:"+version, value:"true");       
  }
  security_hole(port:0, extra:report);
 }

 if ( ereg(pattern:"Mac OS X 10\.([3-9]|2\.8)", string:os ) )
 {
  set_kb_item(name:"CVE-2003-0542", value:TRUE);
  set_kb_item(name:"CVE-2003-0543", value:TRUE);
  set_kb_item(name:"CVE-2003-0544", value:TRUE);
  set_kb_item(name:"CVE-2003-0545", value:TRUE);
 }





 if ( ereg(pattern:"Mac OS X 10\.3\.[0-8]", string:os ))
 {
  report = "
The remote host is running a version of Mac OS X 10.3 which is older
than version 10.3.9.

Apple's newest security updates require Mac OS X 10.3.9 to be applied
properly. The remote host should be upgraded to this version as soon
as possible.
";

  if (defined_func("report_xml_tag"))
  {
    report_xml_tag(tag:"operating-system-unsupported", value:"true");
    report_xml_tag(tag:"UnsupportedProduct:apple:mac_os_x:"+version, value:"true");       
  }
  security_hole(port:0, extra:report);
 }

 if ( ereg(pattern:"Mac OS X 10\.(3\.[3-9]|[4-9])", string:os ))
 {
    set_kb_item(name:"CVE-2004-0174", value:TRUE);
    set_kb_item(name:"CVE-2003-0020", value:TRUE);
 }


 if ( ereg(pattern:"Mac OS X 10\.(3\.[4-9]|[4-9])", string:os))
 {
   set_kb_item(name:"CVE-2004-0174", value:TRUE);
   set_kb_item(name:"CVE-2003-0020", value:TRUE);
   set_kb_item(name:"CVE-2004-0079", value:TRUE);
   set_kb_item(name:"CVE-2004-0081", value:TRUE);
   set_kb_item(name:"CVE-2004-0112", value:TRUE);
 }

 if ( ereg(pattern:"Mac OS X 10\.(3\.[5-9]|[4-9])", string:os))
 {
   set_kb_item(name:"CVE-2002-1363", value:TRUE);
   set_kb_item(name:"CVE-2004-0421", value:TRUE);
   set_kb_item(name:"CVE-2004-0597", value:TRUE);
   set_kb_item(name:"CVE-2004-0598", value:TRUE);
   set_kb_item(name:"CVE-2004-0599", value:TRUE);
   set_kb_item(name:"CVE-2004-0743", value:TRUE);
   set_kb_item(name:"CVE-2004-0744", value:TRUE);
 }
 if ( ereg(pattern:"Mac OS X 10\.(3\.[7-9]|[4-9])", string:os))
 {
   set_kb_item(name:"CVE-2004-1082", value:TRUE);
   set_kb_item(name:"CVE-2003-0020", value:TRUE);
   set_kb_item(name:"CVE-2003-0987", value:TRUE);
   set_kb_item(name:"CVE-2004-0174", value:TRUE);
   set_kb_item(name:"CVE-2004-0488", value:TRUE);
   set_kb_item(name:"CVE-2004-0492", value:TRUE);
   set_kb_item(name:"CVE-2004-0885", value:TRUE);
   set_kb_item(name:"CVE-2004-0940", value:TRUE);
   set_kb_item(name:"CVE-2004-1083", value:TRUE);
   set_kb_item(name:"CVE-2004-1084", value:TRUE);
   set_kb_item(name:"CVE-2004-0747", value:TRUE);
   set_kb_item(name:"CVE-2004-0786", value:TRUE);
   set_kb_item(name:"CVE-2004-0751", value:TRUE);
   set_kb_item(name:"CVE-2004-0748", value:TRUE);
   set_kb_item(name:"CVE-2004-1081", value:TRUE);
   set_kb_item(name:"CVE-2004-0803", value:TRUE);
   set_kb_item(name:"CVE-2004-0804", value:TRUE);
   set_kb_item(name:"CVE-2004-0886", value:TRUE);
   set_kb_item(name:"CVE-2004-1089", value:TRUE);
   set_kb_item(name:"CVE-2004-1085", value:TRUE);
   set_kb_item(name:"CVE-2004-0642", value:TRUE);
   set_kb_item(name:"CVE-2004-0643", value:TRUE);
   set_kb_item(name:"CVE-2004-0644", value:TRUE);
   set_kb_item(name:"CVE-2004-0772", value:TRUE);
   set_kb_item(name:"CVE-2004-1088", value:TRUE);
   set_kb_item(name:"CVE-2004-1086", value:TRUE);
   set_kb_item(name:"CVE-2004-1123", value:TRUE);
   set_kb_item(name:"CVE-2004-1121", value:TRUE);
   set_kb_item(name:"CVE-2004-1122", value:TRUE);
   set_kb_item(name:"CVE-2004-1087", value:TRUE);
 }
}

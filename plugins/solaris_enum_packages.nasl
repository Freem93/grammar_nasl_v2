#
#  (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);

include("compat.inc");

if (description) {
  script_id(29217);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2011/03/21 14:03:09 $");

  script_name(english:"Solaris Installed Package Enumeration (credentialed check)");

  script_summary(english:"Displays the list of packages installed on the remote software"); 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to enumerate installed packages on the remote Solaris host, via 
SSH." );
 script_set_attribute(attribute:"description", value:
"This plugin lists the packages installed on the remote Solaris host by calling 
pkginfo." );
 script_set_attribute(attribute:"solution", value:
"Remove software that is not compliant with your company policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/04");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Solaris/pkginfo");
  exit(0);
}

#

pkg = get_kb_list("Solaris/Packages/Versions/*");
if ( isnull(pkg) ) exit(0);
report = NULL;
foreach name ( keys(pkg) )
{
 version = chomp(pkg[name]);
 name -= "Solaris/Packages/Versions/";
 report += name + " version " + version + '\n';
}

if ( strlen(report) )
{
 security_note(port:0, extra:'Here is the list of packages installed on the remote Solaris host :\n\n' + report);
}

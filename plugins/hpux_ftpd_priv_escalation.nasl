#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33899);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2008-1668");
  script_bugtraq_id(30666);
  script_osvdb_id(48358);
  script_xref(name:"Secunia", value:"31471");

  script_name(english:"HP-UX ftpd PAM Authentication Configuration Weakness Authentication Bypass");
  script_summary(english:"Checks ftp banner");

 script_set_attribute(attribute:"synopsis", value:
"The remote ftp server may allow remote privileged access." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of the HP-UX FTP server running
on the remote host is at a patch level before PHNE_38458.  Such
versions reportedly contain a vulnerability that in
certain account configurations could be exploited by an anonymous
remote attacker to gain privileged access. 

Note that successful exploitation requires that pam is used for
authenticating FTP users and that pam authentication passes when a
user tries to log in while getpwnam returns NULL.  This could occur,
for example, if LDAP is used for pam authentication, the nsswitch.conf
file does not include 'ldap' as a source for the 'passwd' database,
and the attacker tries to log in with a username included in the LDAP
directory." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/15189" );
 script_set_attribute(attribute:"see_also", value:"ftp://us-ffs.external.hp.com/hp-ux_patches/s700_800/11.X/PHNE_38458.txt" );
 script_set_attribute(attribute:"see_also", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/831" );
 script_set_attribute(attribute:"solution", value:
"Apply patch PHNE_38458 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/15");
 script_cvs_date("$Date: 2015/01/15 16:37:16 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");
 script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("global_settings.inc");
include("ftp_func.inc");


port = get_ftp_port(default: 21);


# If it looks like HP-UX 11.11...
banner = get_ftp_banner(port:port);
if (
  banner &&
  " FTP server (Version 1.1.214.4(PHNE_" >< banner
)
{
  # Grab the latest patch.
  patch = strstr(banner, "PHNE_");
  patch = patch - strstr(patch, ")");

  if (
    patch && 
    patch =~ "^PHNE_(36192|36129|34544|33412|31931|30990|30432|29461|27765|23950)$"
  )
  {
    if (report_verbosity)
    {
      report = strcat(
        '\n',
        'The remote FTP server appears to be from HP-UX 11.11 with patch\n',
        patch, ' based on the following banner :\n',
        '\n',
        '  ', banner, '\n'
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}

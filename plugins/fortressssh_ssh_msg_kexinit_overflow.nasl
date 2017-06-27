#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21589);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-2421");
  script_bugtraq_id(17991);
  script_osvdb_id(25535);

  script_name(english:"FortressSSH SSH_MSG_KEXINIT Logging Remote Overflow");
  script_summary(english:"Does a banner check for FortressSSH");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is affected by a remote buffer overflow issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running FortressSSH, an enterprise-class SSH server
for Windows. 

According to its banner, the installed version of this software
reportedly contains a buffer overflow vulnerability involving a
boundary error in the logging of contents of 'SSH_MSG_KEXINIT'
messages.  An unauthenticated attacker may be able to leverage this
issue to crash the affected application or to execute arbitrary code
on the affected host" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/16");
 script_cvs_date("$Date: 2011/03/16 13:37:58 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


port = get_kb_item("Services/ssh");
if (!port) port = 22;
if (!get_port_state(port)) exit(0);


# Get the version number from the banner.
banner = get_kb_item("SSH/banner/" + port);
if (!banner) exit(0);
if ("Pragma FortressSSH" >!< banner) exit(0);

pat = "Pragma FortressSSH (.+)";
ver = NULL;
matches = egrep(string:banner, pattern:pat);
if (matches)
{
  foreach match (split(matches))
  {
    match = chomp(match);
    ver = eregmatch(pattern:pat, string:match);
    if (!isnull(ver))
    {
      ver = ver[1];
      break;
    }
  }
}


# There's a problem if the version's <= 4.0.7.20.
if (!isnull(ver))
{
  iver = split(ver, sep:'.', keep:FALSE);
  if (
    int(iver[0]) < 4 ||
    (
      int(iver[0]) == 4 && int(iver[1]) == 0 &&
      (
        int(iver[2]) < 7 ||
        (int(iver[2]) == 7 && int(iver[3]) <= 20)
      )
    )
  ) security_hole(port);
}

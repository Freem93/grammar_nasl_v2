#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: Damien Miller <djm@cvs.openbsd.org>
# To: openssh-unix-announce@mindrot.org
# Subject: Multiple PAM vulnerabilities in portable OpenSSH
# also covers CVE-2001-1380


include("compat.inc");

if (description)
{
 script_id(11848);
 script_version ("$Revision: 1.26 $");
 script_cvs_date("$Date: 2012/12/10 03:02:35 $");

 script_cve_id("CVE-2003-0786", "CVE-2003-0787");
 script_bugtraq_id(8677);
 script_osvdb_id(6071, 6072);
 script_xref(name:"CERT", value:"602204");
 
 script_name(english:"OpenSSH < 3.7.1p2 Multiple Remote Vulnerabilities");
 script_summary(english:"Checks for the remote SSH version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application which may allow an 
attacker to login potentially as root without password." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be
running OpenSSH 3.7p1 or 3.7.1p1. These versions are 
vulnerable to a flaw in the way they handle PAM 
authentication when PrivilegeSeparation is disabled.

Successful exploitation of this issue may allow an 
attacker to gain a shell on the remote host using a
null password." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 3.7.1p2 or disable PAM support in sshd_config" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/09/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/09/23");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2012 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("ssh_detect.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Windows not affected.
os = get_kb_item("Host/OS");
if (! get_kb_item("Settings/PCI_DSS") && !isnull(os))
{
  if ("Linux" >!< os && "SCO" >!< os) exit(0);
}

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/"+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) exit(1, "The banner from the OpenSSH server on port "+port+" indicates patches may have been backported.");

if (ereg(pattern:"openssh[-_]3\.7(\.1)?p1", string:bp_banner))
  security_hole(port);

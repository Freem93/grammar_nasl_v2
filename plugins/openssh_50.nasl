#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31737);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/12 14:46:29 $");

  script_cve_id("CVE-2008-1483", "CVE-2008-3234");
  script_bugtraq_id(28444);
  script_osvdb_id(43745, 48791);
  script_xref(name:"Secunia", value:"29522");

  script_name(english:"OpenSSH X11 Forwarding Session Hijacking");
  script_summary(english:"Checks OpenSSH server version");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service is prone to an X11 session hijacking
vulnerability." );
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of SSH installed on the remote
host is older than 5.0.  Such versions may allow a local user to
hijack X11 sessions because it improperly binds TCP ports on the local
IPv6 interface if the corresponding ports on the IPv4 interface are in
use." );
  script_set_attribute(attribute:"see_also", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=463011" );
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.org/txt/release-5.0" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 5.0 or later." );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/03");
  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
 
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/"+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) exit(1, "The banner from the OpenSSH server on port "+port+" indicates patches may have been backported.");

if (bp_banner =~ "openssh[-_][0-4]\.")
{
  if (report_verbosity)
  {
    report =
      '\nThe remote OpenSSH server returned the following banner :' +
      '\n' +
      '\n' + banner +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}

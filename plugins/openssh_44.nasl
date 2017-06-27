#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) 
{
  script_id(22466);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2006-4924", "CVE-2006-4925", "CVE-2006-5051", "CVE-2006-5052", "CVE-2006-5229", "CVE-2007-3102", "CVE-2008-4109");
  script_bugtraq_id(20216, 20241, 20245);
  script_osvdb_id(29152, 29264, 29266, 29494, 32721, 39214);

  script_name(english:"OpenSSH < 4.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of OpenSSH");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is affected by multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH installed on the
remote host is affected by multiple vulnerabilities :

  - A race condition exists that may allow an
    unauthenticated, remote attacker to crash the service 
    or, on portable OpenSSH, possibly execute code on the 
    affected host.  Note that successful exploitation 
    requires that GSSAPI authentication be enabled.
    
  - A flaw exists that may allow an attacker to determine 
    the validity of usernames on some platforms. Note that 
    this issue requires that GSSAPI authentication be 
    enabled.

  - When SSH version 1 is used, an issue can be triggered 
    via an SSH packet that contains duplicate blocks that 
    could result in a loss of availability for the service.

  - On Fedora Core 6 (and possibly other systems), an
    unspecified vulnerability in the
    linux_audit_record_event() function allows remote
    attackers to inject incorrect information into
    audit logs.");

  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-4.4" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 4.4 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264, 362, 399);
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/28");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/28");
  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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

if (!get_kb_item("Settings/PCI_DSS"))
{
  auth = get_kb_item_or_exit("SSH/supportedauth/" + port);
  if ("gssapi" >!< auth) exit(0, "The SSH service on port "+port+" doesn't support GSSAPI.");
}

if (bp_banner =~ "openssh[-_]([0-3]\.|4\.[0-3]([^0-9]|$))")
  security_hole(port);

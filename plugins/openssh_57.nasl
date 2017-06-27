#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(44081);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2010-4478", "CVE-2012-0814");
  script_bugtraq_id(45304, 51702);
  script_osvdb_id(69658, 78706);

  script_name(english:"OpenSSH < 5.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service may be affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is earlier than 5.7.  Versions before 5.7 may be affected by the 
following vulnerabilities :

  - A security bypass vulnerability because OpenSSH does not 
    properly validate the public parameters in the J-PAKE
    protocol.  This could allow an attacker to authenticate 
    without the shared secret.  Note that this issue is only
    exploitable when OpenSSH is built with J-PAKE support,
    which is currently experimental and disabled by default, 
    and that Nessus has not checked whether J-PAKE support
    is indeed enabled. (CVE-2010-4478)

  - The auth_parse_options function in auth-options.c in 
    sshd provides debug messages containing authorized_keys
    command options, which allows remote, authenticated 
    users to obtain potentially sensitive information by 
    reading these messages. (CVE-2012-0814)");

  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 5.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"http://seb.dbzteam.org/crypto/jpake-session-key-retrieval.pdf");
  script_set_attribute(attribute:"see_also", value:"http://www.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/jpake.c#rev1.5");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f1722f0");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_require_keys("Settings/ParanoidReport");

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

# Check the version in the banner.
match = eregmatch(string:bp_banner, pattern:'openssh[-_]([0-9][-._0-9a-z]+)');
if (isnull(match)) exit(1, 'Could not parse the version string from the banner on port '+port+'.');

version = match[1];
if (version =~ '^([0-4]\\.|5\\.[0-6](\\.|[^\\.0-9]|$))')
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.7\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, 'The OpenSSH server on port '+port+' is not affected as it\'s version '+version+'.');

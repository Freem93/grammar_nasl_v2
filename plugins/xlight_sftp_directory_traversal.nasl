#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(47680);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2012/05/04 16:59:28 $");

  script_cve_id("CVE-2010-2695");
  script_bugtraq_id(41399);
  script_osvdb_id(66037);
  script_xref(name:"Secunia", value:"40473");

  script_name(english:"XLight FTP Server 3.x SFTP Directory Traversal");
  script_summary(english:"Checks version of XLight SFTP service");

  script_set_attribute(attribute:"synopsis", value:
"The remote SFTP service is affected by a directory traversal
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its SSH banner, the version of XLight FTP server
listening on the remote host is potentially affected by a directory
traversal vulnerability in its SFTP service.  A remote, authenticated
attacker, exploiting this flaw, can read and modify arbitrary files on
the remote host. 

Note that this vulnerability only affects XLight FTP server 3.x as the
SFTP service was first introduced in version 3.0.");

  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/512192/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.xlightftpd.com/whatsnew.htm");
  script_set_attribute(attribute:"solution", value:"Upgrade to XLight FTP Server 3.6 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/08");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh");

  exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/ssh");
if (!port) exit(0, "The 'Services/ssh' KB item is missing.");
if (!get_port_state(port)) exit(1, "Port "+port+" is not open.");

banner = get_kb_item("SSH/banner/"+port);
if (!banner) exit(1, "Failed to retrieve the SSH banner from the service on port "+port+".");
if ('xlightftpd' >!< banner) exit(0, "The banner from the SSH service on port "+port+" does not appear to be XLight.");

matches = eregmatch(pattern:'^SSH.*xlightftpd_(release_)?([0-9\\.]+)$', string:banner);
if (isnull(matches) || matches[2] !~ '[0-9]\\.[0-9\\.]+') exit(1, "Failed to extract the version number from the SSH service on port "+port+".");
version = matches[2];

if (version =~ '^3\\.[0-5]($|\\.)')
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  SSH banner        : ' + banner + 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 3.6.0 \n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
}
else exit(0, 'The host is not affected because XLight SFTP version ' +version+' is installed on port '+port+'.');

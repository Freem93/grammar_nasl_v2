#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52704);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id("CVE-2011-0762");
  script_bugtraq_id(46617);
  script_osvdb_id(73340);
  script_xref(name:"EDB-ID", value:"16270");

  script_name(english:"vsftpd vsf_filename_passes_filter Function Denial of Service");
  script_summary(english:"Checks vsftpd version");

  script_set_attribute(attribute:"synopsis", value:"The remote FTP server is prone to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of vsftpd
listening on the remote server is earlier than 2.3.3 and, as such, may
be affected by a denial of service vulnerability.

An error exists in the function 'vsf_filename_passes_filter()' in
'ls.c' that allows resource intensive glob expressions to be processed
with the 'STAT' command. Using numerous IP addresses to bypass an
FTP-sessions-per-IP-address limit, a remote attacker can carry out a
denial of service attack.

Note that Nessus did not actually test for the flaw but instead has
relied on the version in vsftpd's banner.");
  script_set_attribute(attribute:"see_also", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/46617.c");
  script_set_attribute(attribute:"see_also", value:"ftp://vsftpd.beasts.org/users/cevans/untar/vsftpd-2.3.3/Changelog");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Mar/9");
  script_set_attribute(attribute:"solution", value:
"Update to vsftpd 2.3.4 or later. [While version 2.3.3 actually
addresses this issue, 2.3.4 was released the same day to address a
problem compiling the earlier version.]");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("vsftpd_detect.nasl");
  script_require_keys("ftp/vsftpd", "Settings/ParanoidReport");
  script_require_ports("Services/ftp");

  exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_ftp_port(default: 21);

version = get_kb_item_or_exit("ftp/"+port+"/vsftpd/version");
source  = get_kb_item_or_exit("ftp/"+port+"/vsftpd/version_source");

fixed_version = '2.3.3';
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Source            : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.3.4\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The vsftpd " + version + " install listening on port " + port + " is not affected.");

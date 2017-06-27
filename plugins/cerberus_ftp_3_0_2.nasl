#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40821);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_bugtraq_id(36134);
  script_osvdb_id(57398);
  script_xref(name:"EDB-ID", value:"9515");
  script_xref(name:"Secunia", value:"36456");

  script_name(english:"Cerberus FTP Server Command Processing DoS");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The FTP server installed on the remote Windows host has a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cerberus FTP server on the remote host has a denial of
service vulnerability.  Sending a very long argument (1400 bytes or
more) to any command causes the server to crash.  This reportedly does
not result in memory corruption - the vulnerable versions abnormally
terminate when a long argument is received (before any data is
successfully copied into the destination buffer).  A remote attacker
could exploit this issue to cause a denial of service.");
  script_set_attribute(attribute:"see_also", value:"http://cerberusftp.com/phpBB3/viewtopic.php?f=4&t=2411");
  script_set_attribute(attribute:"see_also", value:"https://www.cerberusftp.com/products/releasenotes.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cerberus FTP server 3.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cerberusftp:ftp_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("cerberus_ftp_installed.nasl");
  script_require_keys("SMB/CerberusFTP/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

installs = get_kb_list("SMB/CerberusFTP/*/version");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Cerberus FTP");

fixed = '3.0.2.0';

info = "";
not_vuln_installs = make_list();

foreach install (keys(installs))
{
  ver = installs[install];
  path = (install - "/version") - "SMB/CerberusFTP/";;

  # Testing indicates this doesn't affect the 2.x branch. Version 3.0.0 is likely
  # affected, and 3.0.1 is definitely affected (per the developer)
  if (ver =~ "3\." && ver_compare(ver:ver, fix:fixed) < 0)
  {
    info +=
      '\n' +
      '\n  Path              : ' + path  +
      '\n  Installed version : ' + ver   +
      '\n  Fixed version     : ' + fixed +
      '\n';
  }
  else not_vuln_installs = make_list(not_vuln_installs, ver + " under " + path);
}

if (info)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0) security_warning(port:port, extra:info);
  else security_warning(port);

  exit(0);
}
else
{
  installs = max_index(not_vuln_installs);
  if (installs == 0) audit(AUDIT_NOT_INST, "Cerberus FTP");
  else if (installs == 1) audit(AUDIT_INST_VER_NOT_VULN, "Cerberus FTP " + not_vuln_installs[0]);
  else exit(0, "The Cerberus FTP installs (" + join(not_vuln_installs, sep:", ") + ") are not affected.");
}

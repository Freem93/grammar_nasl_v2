#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(76459);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/14 15:38:18 $");

  script_bugtraq_id(67707);
  script_osvdb_id(107529);

  script_name(english:"Cerberus FTP Server 6.x < 6.0.9.0 / 7.x < 7.0.0.2 SSH FTP Account Enumeration");
  script_summary(english:"Performs a version check.");

  script_set_attribute(attribute:"synopsis", value:
"The FTP server installed on the remote Windows host is affected by an
unauthorized information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cerberus FTP Server on the remote host is version 6.x
prior to 6.0.9.0 or version 7.x prior to 7.0.0.2. It is, therefore,
affected by an unauthorized information disclosure vulnerability.

A remote attacker can enumerate user accounts via an analysis of
responses from the SSH FTP service.");
  # http://www.cerberusftp.com/products/releasenotes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c18bc396");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cerberus FTP Server 6.0.9.0 / 7.0.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cerberusftp:ftp_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("cerberus_ftp_installed.nasl");
  script_require_keys("SMB/CerberusFTP/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/CerberusFTP/Installed");
installs = get_kb_list_or_exit("SMB/CerberusFTP/*/version");
kb_entry = branch(keys(installs));
kb_base = kb_entry - "/version";

ver  = get_kb_item_or_exit(kb_entry);
file_name = get_kb_item_or_exit(kb_base + "/file");

kb_pieces = split(kb_base, sep:"/");
file = kb_pieces[2] + "\" + file_name;

# It appears the 5.x line does not suffer from this problem
if (ver =~ "^7\." && ver_compare(ver:ver, fix:'7.0.0.2', strict:FALSE) < 0)
  fix = '7.0.0.2';
else if (ver =~ "^6\." && ver_compare(ver:ver, fix:'6.0.9.0', strict:FALSE) < 0)
  fix = '6.0.9.0';
else audit(AUDIT_INST_PATH_NOT_VULN, "Cerberus FTP Server", ver, file);

if (report_paranoia < 2)
{
  ssh_ftp_active = get_kb_item("SMB/CerberusFTP/active_sshftp");
  if (!ssh_ftp_active) exit(0, "The Cerberus FTP Server's SSH FTP service does not appear to be enabled.");
}

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  File              : ' + file +
    '\n  Installed version : ' + ver  +
    '\n  Fixed version     : ' + fix  +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);

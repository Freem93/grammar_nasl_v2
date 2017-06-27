#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(63559);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2012-2999");
  script_bugtraq_id(55788);	
  script_osvdb_id(85748);
  script_xref(name:"CERT", value:"989684");

  script_name(english:"Cerberus FTP Server < 5.0.5.0 Cross-Site Request Forgery");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The FTP server installed on the remote Windows host has a cross-site
request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cerberus FTP server on the remote host is earlier than
5.0.5.0.  As such, it is potentially affected by a cross-site request
forgery (CSRF) vulnerability that can be used to trick an authenticated
administrator into making unintended changes to the application.");
  script_set_attribute(attribute:"see_also", value:"https://www.cerberusftp.com/products/releasenotes.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cerberus FTP server 5.0.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/16");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cerberusftp:ftp_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("cerberus_ftp_installed.nasl");
  script_require_keys("SMB/CerberusFTP/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

installs = get_kb_list("SMB/CerberusFTP/*/version");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Cerberus FTP");

fixed = '5.0.5.0';

info = "";
not_vuln_installs = make_list();

foreach install (keys(installs))
{
  ver = installs[install];
  path = (install - "/version") - "SMB/CerberusFTP/";;

  if (ver_compare(ver:ver, fix:fixed) < 0)
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
  set_kb_item(name:"www/0/XSRF", value:TRUE);
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

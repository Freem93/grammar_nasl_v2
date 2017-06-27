#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(14818);
  script_version ("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id("CVE-2004-0200");
  script_bugtraq_id(11173);
  script_osvdb_id(9951);
  script_xref(name:"MSFT", value:"MS04-028");

  script_name(english:"MS04-028 Exploitation Backdoor Account Detection");
  script_summary(english:"Logs in as user 'X' with no password.");
 
  script_set_attribute(attribute:"synopsis", value:
"It is possible to log into the remote host without a password.");
  script_set_attribute(attribute:"description", value:
"It was possible to log into the remote host with the login 'X' and a
blank password. 

A widely available exploit, using one of the vulnerabilities described
in the Microsoft Bulletin MS04-028 creates such an account.  This
probably means that the remote host has been compromised by the use of
this exploit.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Sep/149" );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms04-028" );
  script_set_attribute(attribute:"solution", value:
"Re-install the operating system on this host, as it has likely been compromised.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_login.nasl");
  script_require_ports(139, 445);
  script_exclude_keys("global_settings/supplied_logins_only", "SMB/any_login");

  exit(0);
}

#
include("audit.inc");
include("smb_func.inc");
include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("SMB/any_login")) exit(0, "The remote host authenticates users as 'Guest'.");
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

login = "X";
pass  = "";

port = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED,port);
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:rand_str(length:8), password:"", domain:NULL, share:"IPC$");
NetUseDel();
if (r == 1) audit(AUDIT_SHARE_FAIL, "IPC$");

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login, password:pass, domain:NULL, share:"IPC$");
if (r == 1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to gain access using the following credentials :\n' +
      '\n' +
      '  User     : ' + login + '\n' +
      '  Password : ' + pass + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  NetUseDel();
  exit(0);
}
else
{
  NetUseDel();
  audit(AUDIT_HOST_NOT, 'affected');
}

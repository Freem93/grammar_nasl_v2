#
# (C) Tenable Network Security, Inc.
#

# 09.16.MS03-039-exp.c.php

include( 'compat.inc' );

if(description)
{
  script_id(11839);
  script_version ("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/12/09 20:54:59 $");

  script_cve_id("CVE-2003-0528");
  script_bugtraq_id(8459);
  script_osvdb_id(2535);
  script_xref(name:"MSFT", value:"MS03-039");

  script_name(english:"MS03-039 Exploitation Backdoor Account Detection");
  script_summary(english:"Logs in as 'e'/'asd#321'");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote host has evidence of being compromised by a widely known exploit."
  );
  script_set_attribute(
    attribute:'description',
    value:"It was possible to log into the remote host with the login 'e' and
the password 'asd#321'.

A widely available exploit, using one of the vulnerabilities described
in the Microsoft Bulletin MS03-039 creates such an account. This 
probably means that the remote host has been compromised by the use of 
this exploit."
  );
  script_set_attribute(
    attribute:'solution',
    value:"Re-install the operating system on this host, as it has been compromised."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(
    attribute:'see_also',
    value:"http://technet.microsoft.com/en-us/security/bulletin/ms03-039"
  );
  script_set_attribute(
    attribute:'see_also',
    value:"http://seclists.org/fulldisclosure/2003/Sep/834"
  );

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/09/17");
 
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

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

login = "e";
pass  = "asd#321";

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

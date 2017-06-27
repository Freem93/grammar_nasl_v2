#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10079);
 script_version("$Revision: 1.52 $");
 script_cvs_date("$Date: 2017/05/05 17:46:22 $");

 script_cve_id("CVE-1999-0497");
 script_bugtraq_id(83206);
 script_osvdb_id(69);

 script_name(english:"Anonymous FTP Enabled");
 script_summary(english:"Checks if the remote ftp server accepts anonymous logins.");

 script_set_attribute(attribute:"synopsis", value:
"Anonymous logins are allowed on the remote FTP server.");
 script_set_attribute(attribute:"description", value:
"Nessus has detected that the FTP server running on the remote host
allows anonymous logins. Therefore, any remote user may connect and
authenticate to the server without providing a password or unique
credentials. This allows the user to access any files made available
by the FTP server.");
 script_set_attribute(attribute:"solution", value:
"Disable anonymous FTP if it is not required. Routinely check the FTP
server to ensure that sensitive content is not being made available.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

 script_set_attribute(attribute:"vuln_publication_date", value:"1993/07/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 1999-2017 Tenable Network Security, Inc.");

 script_dependencie("logins.nasl", "smtp_settings.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

port = get_ftp_port(default: 21);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


anon_accts = make_list(
  'anonymous',
  'ftp'
);

domain = get_kb_item("Settings/third_party_domain");
if(!domain) domain = "nessus.org";

pass = string("nessus@", domain);

foreach acct (anon_accts)
{
  soc = open_sock_tcp(port);
  if (soc)
  {
    r = ftp_authenticate(socket:soc, user:acct, pass:pass);
    if (r)
    {
      port2 = ftp_pasv(socket:soc);
      if (port2)
      {
        soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
        if (soc2)
        {
          send(socket:soc, data:'LIST\r\n');
          listing = ftp_recv_listing(socket:soc2);
          close(soc2);
        }
      }

      if (strlen(listing))
      {
        report = string ("The contents of the remote FTP root are :\n", listing);
      }

      if (report) security_warning(port:port, extra: report);
      else security_warning(port);

      set_kb_item(name:"ftp/anonymous", value:TRUE);
      set_kb_item(name:"ftp/"+port+"/anonymous", value:TRUE);
      user_password = get_kb_item("ftp/password");
      if (!user_password)
      {
        if (! get_kb_item("ftp/login"))
          set_kb_item(name:"ftp/login", value:acct);
        set_kb_item(name:"ftp/password", value:pass);
      }
      close(soc);
      exit(0);
    }
    close(soc);
  }
}

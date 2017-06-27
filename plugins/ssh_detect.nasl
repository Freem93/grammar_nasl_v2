#TRUSTED 7488ddbdecec766003c287dc99a280c49ba007185a352cd65b73f39ac2d704784eea9379e8ddb0f6750b6de56ac10e01275d66acde8d74bad0c55f157ddbe3dc44ae7de089d8126fc4ae61e44d36cd3bc277a5eed0d27728d6db513e6b752288e1ebc80f8ebfc914c04622ef338a8beb598a8c598b52ee7ae2d9865a396940c272d21b95959eeb4236c02182df25d8886a020c6353887d39f3ce642ad5d24a06d1f9863dc3f05a001b0314c884081e1cfed6dae37ee4676fb6365e347fb4a7e6145457980ed488b71e01165cdd1dd451b7792660106c7aaeed7fb622354bc0d002f1a1fad20aa9dec5eaa4d9ca0b6ba7adf93ddc6d4288ea718e758f3051ed734322326c68bb26b628c6e4ee4355b12c3beeee5689531987157fdf07996ed72ee7c5d583800faa714ed5833baa790938a3fda68bbace6637427cdf6b37ab35a92ede51ffa51b89e4ca9b0f3b3899678f9cd04a1dfb094942b56129bc90153d333ca767e1a9046157101a7b140c43287e8d00ba73a0b93b1f53d5421cc01eba9eaa3831fc451c94dcb8a2745246d1bfbe18116c10b50d92db06c395f06c636e99818cbb034f7076a3b8f3bbf292f454d75ae26dc8b907f73a81be392417790d7d9ba6ff5914d82e7fbf78318c24a9c34e5deb6c4fa4fb71023379e7c3518b14d91bd17af9626f33396a08ac78744e812a9b7ddf4a002dd1f108a77bda57e08a12
#
# (C) Tenable Network Security, Inc.
#
# @@NOTE: The output of this plugin should not be changed
#
#
#

include("compat.inc");

if(description)
{
  script_id(10267);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/07/11");

  script_name(english:"SSH Server Type and Version Information");
  script_summary(english:"SSH Server type and version.");

  script_set_attribute(attribute:"synopsis", value:
"An SSH server is listening on this port.");
  script_set_attribute(attribute:"description", value:
"It is possible to obtain information about the remote SSH server by
sending an empty authentication request.");
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"solution", value:"n/a" );

  script_set_attribute(attribute:"plugin_publication_date", value: "1999/10/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");

  script_require_ports("Services/ssh", 22);
  script_dependencies("find_service1.nasl", "find_service2.nasl", "external_svc_ident.nasl");

  exit(0);
}


#
# The script code starts here
#
global_var debug_level;

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");

if (get_kb_item("global_settings/supplied_logins_only"))
  supplied_logins_only = 1;
else
  supplied_logins_only = 0;

port = get_kb_item("Services/ssh");

if (!port) port = 22;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "SSH");

version = NULL;
if (defined_func("bn_random"))
{
  _ssh_socket = open_sock_tcp(port);
  if ( ! _ssh_socket ) audit(AUDIT_SOCK_FAIL, port, "SSH");
  login = kb_ssh_login();
  password = kb_ssh_password();
  pub = kb_ssh_publickey();
  priv = kb_ssh_privatekey();
  passphrase = kb_ssh_passphrase();
  nofingerprint = FALSE;
  if (isnull(login) && !supplied_logins_only)
  {
    login = "n3ssus";
    password = "n3ssus";
    pub = NULL;
    priv = NULL;
    passphrase = NULL;
    nofingerprint = TRUE;
  }

  ssh_login (login:login, password:password, pub:pub, priv:priv, passphrase:passphrase, nofingerprint:nofingerprint);

  version = get_ssh_server_version ();
  banner = get_ssh_banner ();
  supported = get_ssh_supported_authentication ();
  key = get_server_public_key();
  close(_ssh_socket);
}

if ( empty_or_null(version) )
{
  soc = open_sock_tcp(port);
  if ( ! soc ) audit(AUDIT_SOCK_FAIL, port, "SSH");
  version = recv_line(socket:soc, length:4096);
  if ( !ereg(pattern:"^SSH-", string:version ) ) audit(AUDIT_SERVICE_VER_FAIL, "SSH", port);
  close(soc);
}

if (!version) audit(AUDIT_SERVICE_VER_FAIL, "SSH", port);

set_kb_item(name:"SSH/banner/" + port, value:version);
text = "SSH version : " + version + '\n';

if (supported)
{
  set_kb_item(name:"SSH/supportedauth/" + port, value:supported);
  text += 'SSH supported authentication : ' + supported + '\n';
}

if (banner)
{
  set_kb_item(name:"SSH/textbanner/" + port, value:banner);
  text += 'SSH banner : \n' + banner + '\n';
}

if (key)
{
  fingerprint = hexstr(MD5(key));
  b64_key = base64(str:key);

  if ("ssh-rsa" >< key)
  {
    set_kb_item(name:"SSH/Fingerprint/ssh-rsa/"+port, value:fingerprint);
    set_kb_item(name:"SSH/publickey/ssh-rsa/"+port, value:b64_key);
  }
  else if ("ssh-dss" >< key)
  {
    set_kb_item(name:"SSH/Fingerprint/ssh-dss/"+port, value:fingerprint);
    set_kb_item(name:"SSH/publickey/ssh-dss/"+port, value:b64_key);
  }
}

report = '\n' + text;

security_note(port:port, extra:report);
register_service(port:port, proto: "ssh");

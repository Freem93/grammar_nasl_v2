#TRUSTED 58113465984602e7cc8e6d34a2caeaadeeb89bdd75b8562601aab2f53a76dbc4c022acf410bf2b3d265c458b8d5589c3aa1ee1ce5b9c49ab4f33741e336be6f1f63b01bd2ea42de1e83aadd996aa263fc256f48043ffc4f27a209f8f121ff003688daa8cb976724f8046349ccb959b6502961cf87930ddc3a2b7a9c4862e7b57ba04901d6d3b6b98d8ef8e1856b49410f4c83453817514cbdff697a37c243dda7e26946ba09b8a63d0f7008841a74e1bee75c94711dc48d9b7f1d56c8ece7c676bf4cdd6bc5f6ba2d67a3ed38cb9107bc709e80f016d5bc2ac5e5a8096a0feed0e261a234b83bb6015850668a8daf3616901ae46cdd764f3a0f87b02057bd8cad1071564f3fb9e1b745690456fc8b5d1d579ec3fdf0d6d04c329894e3c4720256918b7942e4c6e0a8a3e8631d04f8080cd3bd23c94ebfad3496a1cfd5cdc5dbb0133f0670a3839ebbf19a9150daa036a4469a9877921f9572f3f051f7bdd283b1e2a0a891ec0349d8f74f58ace04c212d6cba02fe2b6214a03faddb9b1f912b6fe39ae35d94110949ba24e00d6da166896488a037345984d2514f81e1634b86ff15712c5122a416dec2a533f675679d66c0a328f877f14859163972f79a78b2c180d6a6b657c375525e40f002efa0986231a916ed2e134aae0be6e2a6f5d2d6d4beac8a235b3305bbd89c35e0f14eea7a3f1485a6cbdf4e745e2981f0f755694
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64258);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value: "2016/10/07");

  script_bugtraq_id(57537);
  script_osvdb_id(89519);

  script_name(english:"Barracuda Appliances Default Credentials");
  script_summary(english:"Tries to login as product or emailswitch");

  script_set_attribute(attribute:"synopsis", value:"An account on the remote host uses a default password.");
  script_set_attribute(
    attribute:"description",
    value:
"The account 'product' or 'emailswitch' is using a default password.  A
remote, unauthenticated attacker could exploit this to log in as an
unprivileged user.  After logging in, an attacker can log into the local
MySQL server as root without a password.  Additionally, getting access
to a root shell is trivial. 

It is also likely that this host allows remote logins using the 'root',
'cluster', and 'remote' accounts using public key authentication, but
Nessus has not checked for those issues."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Jan/220");
  script_set_attribute(attribute:"see_also", value:"https://www.barracudanetworks.com/support/techalerts#41");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Security Definition 2.0.5 or later.

Note that this fix does not disable access to the root, cluster, or
remote accounts."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

accounts = make_array(
  'product', 'pickle99',
  'emailswitch', 'pickle99'
);

foreach user (sort(keys(accounts)))
{
  port = kb_ssh_transport();
  if (!get_port_state(port))
    audit(AUDIT_PORT_CLOSED, port);
  
  _ssh_socket = open_sock_tcp(port);
  if (!_ssh_socket)
    audit(AUDIT_SOCK_FAIL, port);
  
  pass = accounts[user];
  ret = ssh_login(login:user, password:pass);
  if (ret != 0)
  {
    ssh_close_connection();
    continue;
  }
  
  output = ssh_cmd(cmd:'id', nosh:TRUE, nosudo:TRUE);
  ssh_close_connection();
  
  if ("uid=" >!< output || user >!< output)
    continue;
  
  # research indicates a vulnerable system will only have one of the
  # accounts being tested for, so the plugin can stop after the
  # first successful login
  if (report_verbosity > 0)
  {
    report =
      '\nNessus authenticated via SSH using the following credentials :\n' +
      '\n  Username : ' + user +
      '\n  Password : ' + pass + '\n' +
      '\nAfter authenticating Nessus executed the "id" command which returned :\n\n' +
      chomp(output) + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}

audit(AUDIT_LISTEN_NOT_VULN, 'SSH server', port);

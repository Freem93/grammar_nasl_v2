#TRUSTED a80bcdae56d0f4639b9895c19a13924236e16ca721fe47dfd89f4d4b2436d4510fa4012e8ac0024716723759d37e569c83d70edf1b8bb7e7bed76797d1744a32a80c1673b7bd9974ea013f12b6862f00fd24326c60c7d785c82dae395bce34aa99e87a5a76448064a72623b1f54da545559213ca6ca163548d9ca425d5185cbf4f921bb645bcabb4462e16238d0daae3d2e8496bafe8620e7556a2e6bace76f5820aebf9b5ea12b9ad94d0b0dc091153f1881e50191b83dba47c680bd5a5aa736de20223fd87c3daf66aad9739a998ef9ca6961dac24e3f32cbcca9daf041d64bcf4cdcc944f0183c9ca02906c57c093e6b2ea4d9469f9a60888cc6cbd7327af2ad9e363fbe891b610608f35d62e3fd15ee8705aa5888751d6c122767d50334d302c8954a159471712910bd87e8c71ed784079d620df3d766c0e574e54dabb1252e199ea08f2341ee4e47ca6aa5298ba43da432561f494ce5aa585e3aad9b2fd1c73ddca31346ff95c2e7583b06f27e757d2ce9d920d13a581a0f0ea35bbe675bcb980c77e98d6800ea31b588aef301ac229406bcfecdbfe107ee73f8c1ab0bd6fc04633e90711136346c3c843e221dc479ec428665d3b4f09d03b64506c42a81d4737c8abb564ed587f729f6b34089906c586fde63662f706f239a3027cd6b341867845d0273c42e2336ce6434cdf6dba63093a8aab1c7ca181b0fdba265caa
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87506);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/05/24");

  script_cve_id("CVE-2015-6389");
  script_bugtraq_id(78738);
  script_osvdb_id(131471);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus62707");
  script_xref(name:"IAVA", value:"2015-A-0309");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151209-pca");

  script_name(english:"Cisco Prime Collaboration Assurance Default 'cmuser' Credentials (cisco-sa-20151209-pca)");
  script_summary(english:"Checks the Cisco Prime Collaboration Assurance version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote network management device is protected by default
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Prime Collaboration Assurance device is protected by
default credentials. This is due to an undocumented account that is
created during installation. A remote attacker can exploit this to log
in to the system shell with the default 'cmuser' user account, and
access the shell with a limited set of permissions.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151209-pca
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a078e901");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus62707");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Collaboration Assurance version 11.0 or later.

Alternatively, a workaround is to change the default password for the
'cmuser' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration_assurance");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_prime_collaboration_assurance_detect.nbin");
  script_require_keys("Host/Cisco/PrimeCollaborationAssurance/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");

appname = "Prime Collaboration Assurance";
version = get_kb_item_or_exit("Host/Cisco/PrimeCollaborationAssurance/version");

login    = "cmuser"; # default
password = "cmuser"; # default
flag  = 0;
port  = 0;
extra = '';
report_extra = '';

# Normal version check first
# Affected : < 11.0 per vendor
if (ver_compare(ver:version, fix:"11.0.0",  strict:FALSE) < 0)
  flag++;

# Check the workaround (are default creds gone?).
if (report_paranoia < 2 && flag)
{
  # Do not try this if the user has specified
  # that only user-supplied credentials are okay.
  if (supplied_logins_only)
    audit(AUDIT_SUPPLIED_LOGINS_ONLY);

  # Setup SSH bits
  port = kb_ssh_transport();
  if (!get_port_state(port))
    audit(AUDIT_PORT_CLOSED, port);

  _ssh_socket = open_sock_tcp(port);
  if (!_ssh_socket)
    audit(AUDIT_SOCK_FAIL, port);

  # Attempt the login with default credentials.
  login_result = ssh_login(login:login, password:password);

  # If login fails just keep port at '0' for
  # the version-check reporting.
  if (login_result != 0)
  {
    ssh_close_connection();
    port = 0;
    flag = 0;
  }
  # If login successful, attempt to run 'id'
  else
  {
    ssh_cmd_output = ssh_cmd(cmd:'id', nosh:TRUE, nosudo:TRUE);
    ssh_close_connection();

    if (
      ssh_cmd_output &&
      'uid' >< ssh_cmd_output
    )
    {
      # Login okay; 'id' command okay
      report_extra =
        '\n  After authenticating, Nessus executed the "id" command ' +
        '\n  which returned :' +
        '\n' +
        '\n' +
        chomp(ssh_cmd_output) +
        '\n';
    }
    else
    {
      # Login okay; BUT perhaps account is
      # administratively required to change
      # password before running commands. Or
      # any number of other mechanisms that
      # complete the login process but do not
      # allow 'id' command.
      report_extra =
      '\n  After authenticating, Nessus attempted to execute the "id" ' +
      '\n  command, but the attempt was not successful. This could ' +
      '\n  be due to the account being administratively required to ' +
      '\n  change password at login; however, the account is indeed enabled ' +
      '\n  and accessible with the default password.';
    }
  }
}

if (port || flag)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 11.0' +
      '\n';
    if (report_paranoia == 2)
      report_extra +=
        '\n  Note that Nessus has not attempted to login as the "cmuser" due' +
        '\n  this scan being configured as Paranoid.' +
        '\n';
    security_hole(port:port, extra:report + report_extra);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);

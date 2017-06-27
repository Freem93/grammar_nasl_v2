#TRUSTED 3b584c2f93ce6d732617a0a34372c171d7d1acab388e68f1ef5b32022ecc9c98edf3c51b7d033284dfa6a6eb24d19f7cc93d11192be86efc96843a84d9bd853507bd20151cd2627be88bbc4e82ff0caba42974f063c96050545be9f6d44fcc1347cbc20ca73392d498f09f1416afc184b32e698bcf2e3bc1791d60b3f708a97f3de015b49150b64f13afbed1b74e4ad2eadcff2828812e0fc1e3241eff26184fb1b1ca10768c5e3cc7678809676398aabcf25b9b36c6f4a912e52094e2c43a223080e6753a1ed8ecf1da1da108dbae5a522472be7b2b485c22e0575e650a70a1bcfcfda33e84817a5a9d92302f329cc95cf65dc27e72bc1dbf8084f1e71fc4597ea77e2edee6f407910f4dc9e2d7f17cd239e718e93e558d6f260250c0cdc9c8f6689e08409b32e02977fdc9f81af4896ac84370d0eb56663ed2cab2efad9d5c6d7918a0d78e8c81ea96211bd42335e3a5475d713101a33887d1d6bcc44132203226a098a0721d56ab48d18e8960984a0b624b8e5afb622332ee67d0c4a6a4d9a33682d5d3e5a0ae86711bf722e7cb919aa9875e95fc8322fca543ccc8c970a9a5abad615b1cf7c097e4c87d48ea54315e892ec6c4e5332338d3d5d61d3d41c4a071427f7d5fc3abe2a164bfa8eee2c1afea56f46b6194ff67bf9b8fa5582da4e61890d2e3aab07f74f94270ab4724ab3aee0bd6006f08c0651e28aaa7966592

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72663);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/10/06");

  script_name(english:"SFTP Supported");
  script_summary(english:"Checks if the device supports SFTP");

  script_set_attribute(attribute:"synopsis", value:"The remote SSH service supports SFTP.");
  script_set_attribute(attribute:"description", value:
"The remote SSH service supports the SFTP subsystem. SFTP is a protocol
for generalized file access, file transfer, and file management
functionalities, typically over SSH.

Note that valid credentials are required to determine if SFTP is
supported and also that SFTP support can be enabled selectively for
certain accounts.");
  script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/SSH_File_Transfer_Protocol");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this facility agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_settings.nasl", "ssh_detect.nasl");
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


port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);


if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


# Generate a list of accounts to check.
i = 0;
logins      = make_array();
passwords   = make_array();
passphrases = make_array();
privs       = make_array();
pubs        = make_array();
certs       = make_array();
realms      = make_array();

# - anonymous
logins[i]    = "anonymous";
passwords[i] = SCRIPT_NAME + '@nessus.org';
i++;

# - guest
logins[i]    = "guest";
passwords[i] = SCRIPT_NAME + '@nessus.org';
i++;

# - credentials supplied in the scan policy.
kb_login = kb_ssh_login();
if (strlen(kb_login))
{
  found = FALSE;
  for (k=0; k<i; k++)
  {
    if (kb_login == logins[k])
    {
      found = TRUE;
      break;
    }
  }
  if (!found)
  {
    logins[i]      = kb_login;
    passwords[i]   = kb_ssh_password();
    passphrases[i] = kb_ssh_passphrase();
    privs[i]       = kb_ssh_privatekey();
    pubs[i]        = kb_ssh_publickey();
    certs[i]       = kb_ssh_certificate();
    realms[i]      = kb_ssh_realm();
    i++;
  }
}

if (get_kb_item("Secret/SSH/0/login"))
{
  for (j=0; TRUE; j++)
  {
    login = get_kb_item("Secret/SSH/"+j+"/login");
    if (isnull(login)) break;
    pass = get_kb_item("Secret/SSH/"+j+"/password");

    found = FALSE;
    for (k=0; k<i; k++)
    {
      if (login == logins[k])
      {
        found = TRUE;
        break;
      }
    }

    if (!found)
    {
      logins[i] = login;
      passwords[i] = get_kb_item("Secret/SSH/", j, "/password");
      passphrases[i] = get_kb_item("Secret/SSH/", j, "/passphrase");
      privs[i] = kb_ssh_alt_privatekey(j);
      certs[i] = get_kb_item("Secret/SSH/", j, "/certificate");
      realms[i] = get_kb_item("Kerberos/SSH/", j, "/realm");
      i++;
    }
  }
}
n = i;


# Test each account.
dir = "/";
max_files = 10;
want_reply = (report_paranoia == 0);

checked_logins = make_list();
working_logins = make_list();

report = '';
for (i=0; i<n; i++)
{
  checked_logins = make_list(checked_logins, logins[i]);

  rc = ssh_fxp_open_connection(
    port       : port,
    login      : logins[i],
    password   : passwords[i],
    passphrase : passphrases[i],
    priv       : privs[i],
    pub        : pubs[i],
    cert       : certs[i],
    realm      : realms[i],
    want_reply : want_reply
  );
  if (rc)
  {
    set_kb_item(name:"SSH/"+port+"/sftp/login", value:logins[i]);
    working_logins = make_list(working_logins, logins[i]);

    if (report_verbosity > 0)
    {
      if (strlen(report) == 0)
      {
        report = '\n' + 'Nessus was able to access the SFTP service using the following' +
                 '\n' + 'account :' +
                 '\n' +
                 '\n' + '  ' + logins[i];

        listing = ssh_fxp_get_listing(dir:dir, max_files:max_files);
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
                      '\n' + 'Note that this listing is incomplete and limited to ' + max_files + ' entries.  To' +
                      '\n' + 'list all files, set the \'Report verbosity\' preference in the scan' +
                      '\n' + 'policy to \'Verbose\' and re-scan.' +
                      '\n';
          }
        }
      }
    }

    ssh_fxp_close_connection();
    if (!thorough_tests) break;
  }
}
if (max_index(working_logins) == 0)
{
  ssh_close_connection();
  err_msg = "The SSH service listening on port "+port+" does not support SFTP access for the login";
  if (max_index(checked_logins) > 1) err_msg += "s";
  err_msg += " '" + join(checked_logins, sep:"' / '") + "'.";
  exit(0, err_msg);
}

if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);

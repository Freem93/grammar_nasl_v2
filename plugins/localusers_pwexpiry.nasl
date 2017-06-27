#TRUSTED 940e5373ef34db02ff5c8c1da6c8036dda432edc86a351d99020b7e8a73f95bc6860cfb9a8b3b5acefb325c0f3565fcee1f5c773c5090a9da987b0425d77c853a21c5fd43639b5583ffebbcf5f7d0610cf690c646fbc90d6b417c03e632271e901615d198e18d2790130dcd8504f75c4d6a78fce4ebd49ffc29e24e8783001ac884867f6f1101d9945fab1dc3dc9909bfd404ae5bc67bad539488ebc6f8bcd41f587aa90a6b37483aa17618dd907c487dede894afef6ee241a6b84516874efedf8d3bc897898a42a241830444b47e5f3caf81d192a8787b09368da0296f02fa996b8612986cb47ec9616d8da8c8251a3dfcec3ee04f8744338570b3a75cefc1f23346bf7c666ace23916dc6e3c330c76248da2664f7dadb9090369a81ece97057416df55fc65eb1d235a448a8279452eaec2c7d96bdcfbd8cfe2025fde3818437ebcdc9b09e18ed42c8b505fded67b71b9fdde777698513a549b2ca27738baaadc1122e21a870f09a81286cb0ff86e912fda6b26ee9e6fe4a668011d0f555fd17f848345d388a3175fa5ceb03ce1c3475f2fc0c283297735f8619812166a981652f11f688a17981678d2fd02f1855a027e420e2ee4c4ddbee5033a79ea703cb2a1ff156d45ed8193ac27ab7b4183644dfd10b8fcff8ce53484a7bfa3f11f2f2820cbf18ae95c22c7755b9fee7707d0930622a43d3ad906591233a7ca0a905ed7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83303);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/01/26");

  script_osvdb_id(755);

  script_name(english:"Unix / Linux - Local Users Information : Passwords Never Expire");
  script_summary(english:"Lists local users whose passwords never expire.");

  script_set_attribute(attribute:"synopsis", value:
"At least one local user has a password that never expires.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to list local users
that are enabled and whose passwords never expire.");
  script_set_attribute(attribute:"solution", value:
"Allow or require users to change their passwords regularly.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Do not run against Windows and some Unix-like systems
supported = FALSE;
dist = "";
if (
  get_kb_item("Host/CentOS/release") ||
  get_kb_item("Host/Debian/release") ||
  get_kb_item("Host/Gentoo/release") ||
  get_kb_item("Host/Mandrake/release") ||
  get_kb_item("Host/RedHat/release") ||
  get_kb_item("Host/Slackware/release") ||
  get_kb_item("Host/SuSE/release") ||
  get_kb_item("Host/Ubuntu/release")
)
{
  supported = TRUE;
  dist = "linux";
  field = 5;
}
else if (
  get_kb_item("Host/FreeBSD/release") 
)
{
  supported = TRUE;
  dist = "bsd";
  field = 6;
}

if (!supported) exit(0, "Account expiration checks are not supported on the remote OS at this time.");

# We may support other protocols here
if ( islocalhost() )
{
  if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

if (dist == "linux")
  cmd = "cat /etc/shadow";
else
  cmd = "cat /etc/master.passwd";

validfile = FALSE;
noexpiry = make_list();
buf = info_send_cmd(cmd:cmd);
if (buf)
{
  lines = split(buf);
  if (!empty_or_null(lines))
  {
    foreach line (lines)
    {
      acct_fields = split(line, sep:':', keep:FALSE);
      if (max_index(acct_fields) >= 7)
      {
        validfile = TRUE;
        # Skip locked / expired accounts
        if (acct_fields[1] == '*' || acct_fields[1] == '!' || acct_fields[1] == "!!")
          continue;
        if (dist == "bsd" && acct_fields[1] =~ '\\*LOCKED\\*')
          continue;

        if (dist == "linux" && !empty_or_null(acct_fields[7]))
        {
          if (!empty_or_null(acct_fields[6]))
            timetoexpire = int(acct_fields[6]) * 86400;
          else timetoexpire = 0;

          expire_timestamp = int(acct_fields[7]) * 86400 + timetoexpire;
          current_timestamp = unixtime();
          if (expire_timestamp < current_timestamp)
            continue;
        }

        if (empty_or_null(acct_fields[field - 1]) || int(acct_fields[field - 1]) == 99999 || (dist == "bsd" && acct_fields[field - 1] == 0))
          noexpiry = make_list(noexpiry, acct_fields[0]);
      }
    }
  }
}
else
{
  errmsg = ssh_cmd_error();
  if ('Permission denied' >< errmsg)
    exit(1, "The supplied user account does not have sufficient privileges to read the password file.");
  else
    exit(1, errmsg);
}
if (!validfile)
  exit(1, "The password file did not use the expected format.");

if (!empty_or_null(noexpiry))
{
  count = 0;
  foreach user (noexpiry)
  {
    count += 1;
    set_kb_item(name:"SSH/LocalUsers/PwNeverExpires/"+count, value:user);
  }

  if (report_verbosity > 0)
  {
    report =
      '\nNessus found the following unlocked users with passwords that do not expire :' +
      '\n  - ' + join(noexpiry, sep:'\n  - ') + '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected');

#TRUSTED 70ca5d06f9df8b5db4df0015636d24066074eda57b48b8fd81653be4eb8640611065a6cb9d1c3f4242d62dbc765fa116f87d363558cd8852c129ec1b6ee2259a9001b18648bcf7954dec1d72ea8a598225cc6d7c267aedec8018b28eaa022a773f2e626549e104950a82473615375f954623a854e944d4e0338a00d595494dcca7195e2aa7d8e5d5b77c18592f5daaac9885a207ebb019bf57ead1c2e42bf1874cbc0c5517b2999eb2dafbcb30cc218bba144d5e2c0ed45d18f00cf5ef5d4d2964aa58cf4e90922da0552e471addb0785a382aa9853a1c858f195aa595000205dba8d7967f53558bd1c8b9d45de32eaffea21a3118eb4cb029cfe08099a3a4e871d210de3554d07076e35d54b3153e38541c0c9fd731929cf7b787b9f046857ef2cdc339c4ae6e3ddc8029c9430bc078988ac5c9ce3e3d16e3a4f87d7d3bbf0c224ad0653647cb1b2e22b0e489a3ebb9eeac2a1761184d163a018c4e6b62aa5e6e16aeffce4187874cc6366a6726fb0f465e4bcbb3e78719d33f7ce0acc7ec765c05351d592c98c9170848b7fd19297c4f56e838bb4aefebcb6cb8b2d62697d55843d4791905dfff7e0d748626401794fa8b8811ea1dc78f9a8fa464988b607d7557b36f027e0f2968ce99656eee88102a227fdd3bc9da5eced8353e7b076e2fd43edda5d9c2ba7a0222e8021e92c5894e5181f86043b2722950c1c37892f484
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(59090);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/11/18");

  script_cve_id("CVE-2012-0652");
  script_bugtraq_id(53402);
  script_osvdb_id(82016);

  script_name(english:"Mac OS X FileVault Plaintext Password Logging");
  script_summary(english:"Checks secure.log files for plaintext passwords");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Mac OS X host logs passwords in plaintext."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Plaintext passwords were discovered in a system log file.  Mac OS X
Lion release 10.7.3 enabled a debug logging feature that causes
plaintext passwords to be logged to /var/log/secure.log on systems
that use certain FileVault configurations.  A local attacker in the
admin group or an attacker with physical access to the host could
exploit this to get user passwords, which could be used to gain access
to encrypted partitions."
  );
  script_set_attribute(attribute:"see_also",value:"https://discussions.apple.com/thread/3715366");
  script_set_attribute(attribute:"see_also",value:"https://discussions.apple.com/thread/3872437");
  script_set_attribute(attribute:"see_also",value:"http://cryptome.org/2012/05/apple-filevault-hole.htm");
  script_set_attribute(attribute:"see_also",value:"http://support.apple.com/kb/HT5281");
  script_set_attribute(attribute:"see_also",value:"http://support.apple.com/kb/TS4272");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Mac OS X 10.7.4 or later and securely remove log files
that contain plaintext passwords (refer to article TS4272)."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2012/02/06");
  script_set_attribute(attribute:"patch_publication_date",value:"2012/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("audit.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
ver = get_kb_item_or_exit("Host/MacOSX/Version");

match = eregmatch(string:ver, pattern:'([0-9.]+)');
ver = match[1];

# the vulnerability was introduced in 10.7.3
if (ver_compare(ver:ver, fix:'10.7.3', strict:FALSE) < 0)
  audit(AUDIT_HOST_NOT, 'Mac OS X >= 10.7.3');

cmd = "/usr/bin/bzgrep ': DEBUGLOG |.*, password[^ ]* =' /var/log/secure.log* 2> /dev/null";
output = exec_cmd(cmd:cmd);
if (!strlen(output))
  audit(AUDIT_HOST_NOT, 'affected');

credentials = make_array();

foreach line (split(output, sep:'\n', keep:FALSE))
{
  # this might be asking for trouble because it's unclear how the logger handles things like passwords with ', '
  # in them. at worst, all that should happen is the last character of the password will be reported incorrectly
  logdata = strstr(line, ' | about to call ');
  fields = split(logdata, sep:', ', keep:FALSE);
  user = NULL;
  pass = NULL;

  foreach field (fields)
  {
    usermatch = eregmatch(string:field, pattern:'name = (.+)');
    if (isnull(usermatch))
      usermatch = eregmatch(string:field, pattern:'= /Users/([^/]+)');
    if (!isnull(usermatch))
      user = usermatch[1];

    passmatch = eregmatch(string:field, pattern:'password(AsUTF8String)? = (.+)');
    if (!isnull(passmatch))
    {
      pass = passmatch[2];
      pass = pass[0] + '******' + pass[strlen(pass) - 1];
    }
  }

  if (!isnull(user) && !isnull(pass))
    credentials[user] = pass;
}

if (max_index(keys(credentials)) == 0)
  audit(AUDIT_HOST_NOT, 'affected');

report =
  '\nNessus discovered plaintext passwords by running the following command :\n\n' +
  cmd + '\n' +
  '\nThe following usernames and passwords were extracted (note' +
  '\nthat any passwords displayed have been partially obfuscated) :\n';

foreach user (sort(keys(credentials)))
{
  report +=
    '\n  Username : ' + user +
    '\n  Password : ' + credentials[user] + '\n';
}

security_note(port:0, extra:report);


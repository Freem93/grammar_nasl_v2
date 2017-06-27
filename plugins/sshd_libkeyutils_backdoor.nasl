#TRUSTED 712306e1027ac939e64e75c4d7891e7a0898e8092f9d61be429dc596c2acbf6df13c2645fb5bf8dc8cd5aa8067dc5cd37b427ead29c1d20c8dd3109ba817ad5b69d844c555266d36564c26ad0169a095fb32b69e644c93734cc34a1fb77ab3c91582c584bbc8907cba2463cbf37267670b70645867f796977399a036192aefdc704cf60a6d8e3fdcad8ad1dd73cc0aab77209147c960c00db7bd2d24e874f1acd791a228a77888f00c47af2984d1366ba74969ace1965262d7995ab007966e90d3bdeeeb6e1d6570b976f2f734d487e01ca8efd30886d163e2b1c6c3169223e41fcc72f10c5fbc80fbcdc4403f9b75aae2f78323cc0f017cd97ca9c6711085535cf9977e6c5f5e81d8bf99332ef4b2272a137f0110f5fb1814ee8ecb5a56218ec451e7bdcbe0c433b31422d84e3e0610de408491490131c6df25cf6d755924b93fc927cb1931e1d377bdcd51f27d3c0aa36804c969b5504e5b89bf966fd4f5cda5d0b60bd16ce2ae2189cea9e47490feaab47a9ea4647373f5e8ce948d449f15974c886dc82da4272bb1b1f3932bf84ed240416906073ce23cfdc76925f6ccc2dc6f5ba1d983ee0859028469b4942387730d61f2c08e40fe114d281a4577842d533666c498895b5e4816566e5604d76e268d7678864eaf1c29d6064c951749df2627d9da888dcc4462552a25ad77d8490933d01591379cfe4b844cd58ced0d71
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64913);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/02/28");

  script_name(english:"SSHD libkeyutils Backdoor");
  script_summary(english:"Checks for evidence of a libkeyutils library being trojaned");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host may be compromised."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host appears to contain a trojaned libkeyutils library.  The
trojaned library links to SSHD, steals credentials, and sends spam."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.webhostingtalk.com/showthread.php?t=1235797");
  # http://blog.solidshellsecurity.com/2013/02/18/0day-linuxcentos-sshd-spam-exploit-libkeyutils-so-1-9/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f62cb60d");
  # http://contagiodump.blogspot.com/2013/02/linuxcentos-sshd-spam-exploit.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b03816df");
  # https://isc.sans.edu/diary/SSHD%20rootkit%20in%20the%20wild/15229
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4958f5dd");
  script_set_attribute(attribute:"see_also", value:"http://www.webhostingtalk.com/showpost.php?p=8563741&postcount=284");
  script_set_attribute(
    attribute:"solution",
    value:
"Verify whether or not the system has been compromised.  Restore from
known good backups and investigate the network for further signs of a
compromise, if necessary."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("telnet_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# public reports indicate only RPM-based distros have been infected
rpm_list = get_kb_list_or_exit('Host/*/rpm-list');
rpm_list = make_list(rpm_list);
rpm_list = split(rpm_list[0], sep:'\n', keep:FALSE);

keyutils_rpms = make_list();

foreach line (rpm_list)
{
  fields = split(line, sep:'|', keep:FALSE);
  rpm = fields[0];
  if (rpm =~ "^keyutils-libs-\d")
    keyutils_rpms = make_list(keyutils_rpms, rpm);
}

if (max_index(keyutils_rpms) == 0)
  audit(AUDIT_NOT_INST, 'keyutils-libs');

# initialization required for using info_send_cmd()
if (islocalhost())
{
  if (!defined_func("pread")) audit(AUDIT_FN_UNDEF, 'pread');
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

affected_files = make_array();
rpm_verify = make_array();

foreach rpm (keyutils_rpms)
{
  # verify the files in the rpm package
  rpm_cmd = '/bin/rpm -Vv ' + rpm;
  rpm_output = info_send_cmd(cmd:rpm_cmd);
  output_lines = split(rpm_output, sep:'\n', keep:FALSE);

  foreach line (output_lines)
  {
    # determine if the size and md5sum of any library files have changed
    match = eregmatch(string:line, pattern:"^S.5......\s+(/lib(64)?/libkeyutils.+)$");
    file = match[1];
    if (isnull(file)) continue;

    # if so, check if the file contains the encoded IP address associated with this backdoor.
    # the string below is 78.47.139.110 - each byte is xor'd with 0x81
    encoded_ip = "\xb6\xb9\xaf\xb5\xb6\xaf\xb0\xb2\xb8\xaf\xb0\xb0\xb1";
    cmd = "/bin/grep -P '" + encoded_ip + "' " + file + ' &> /dev/null ; /bin/echo $?';
    results = info_send_cmd(cmd:cmd);

    if (chomp(results) == '0') # avoid false negatives by checking the exit status
    {
      affected_files[file] = cmd;
      rpm_verify[rpm_cmd] = rpm_output;
    }
  }
}

ssh_close_connection();

if (max_index(keys(affected_files)) == 0)
  audit(AUDIT_HOST_NOT, 'affected');

if (report_verbosity > 0)
{
  if (max_index(keys(affected_files)) == 1)
    s = ' appears';
  else
    s = 's appear';

  report =
    '\nThe following file' + s + ' to contain backdoor code :\n\n' +
    join(sort(keys(affected_files)), sep:'\n') +'\n\n' +
    'This was determined by verifying any libkeyutils RPM packages :\n\n' +
    join(sort(keys(rpm_verify)), sep:'\n') + '\n\n' +
    join(sort(make_list(rpm_output)), sep:'\n') + '\n' +
    'And checking if any modified library files contain a string which\n' +
    'can be decoded to "78.47.139.110" (an IP address associated with the\n' +
    'backdoor) :\n\n';
  foreach key (sort(keys(affected_files)))
    report += affected_files[key] + '\n';

  security_hole(port:0, extra:report);
}
else security_hole(0);

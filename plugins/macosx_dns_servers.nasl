#TRUSTED 89137a78bf3b9fbb93f96846e0b42a95fe1f2e0b4dba1e78cd7488544c56c9f28dcd3bfe9ef2d587a433ab407c09828ace1aca54f0dc823e18821617bddff9d6dd25dc057d1bf00327703da19c7d263ba3710593e117e233f582c79af59f3ec3d73f1e005740bc69e0ee6e583f86954c19c24e410e6a89a20d5c1a3423743cc35777a556167cb6a9793ad32b8be6322fb7d9a97dc22e597a2daaea94609c8caee8031ca76afbbf385c5ff1a03fef7f767f3cfa1bab557a6059021cd2fe715a0b392b6330b245d9456cf4a5f7bb8d01ce5705237d630bcd6fdd4fc5ba30ca923f42533cd6f59c0bcb7b87901ebb5e5925d32c36318dc2fd6606b3e33c07ee510550570ad58860a19e13299f62e674beb527e9992e26cf64663b2169488629a1844fe2d948bb580e09aec59a5963c51c9177d6b65cdeb35ea4fa9891280b59cbd313fe268cdaff35f2ac75b8bc7f8add0b09764ab35da12d6071d96b5c3d46101b35d362fa7cab8373b1aa6ad864bfe7913d63aad26abdc6e07a7fa00f9c3b5d3742ada2ca6aabb93c991363bc6d7472c89e8bd11bbb79f76b4c6ecc31066ad0f9591ffe1933da4ec1a3c8a2385c2bc7d741df4918c403baeeddeda00eefd5e5956a4370a8c2abfd43d8538fefc75e65249d81da159fed958b84bb8c1e7275df0493c0586e187626bc689fd779a8ac78e70b4b39e6187ae540a98b197c6217ed64
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(58180);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2012/03/01");

  script_name(english:"Mac OS X DNS Server Enumeration");
  script_summary(english:"Looks in resolv.conf to see which DNS servers are in use");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Nessus enumerated the DNS servers being used by the remote Mac OS X
host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to enumerate the DNS servers configured on the remote
Mac OS X host by looking in /etc/resolv.conf."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
get_kb_item_or_exit("Host/MacOSX/Version");

nameserver_file = '/etc/resolv.conf';
cmd = '/bin/cat ' + nameserver_file;
output = exec_cmd(cmd:cmd);
if (!strlen(output)) exit(1, "Failed to get the version of Safari.");

dns_servers = make_list();

foreach line (split(output, sep:'\n', keep:FALSE))
{
  # extract name servers, ignoring commented lines
  match = eregmatch(string:line, pattern:"^[^#;]*nameserver ([0-9.]+)");
  if (isnull(match)) continue;

  dns_servers = make_list(dns_servers, match[1]);
}

report = NULL;

foreach server (dns_servers)
{
  set_kb_item(name:'resolv.conf/nameserver', value:server);
  report += server + '\n';
}

if (isnull(report))
  exit(0, "No DNS servers were found in '" + nameserver_file + "'.");

if (report_verbosity > 0)
{
  report = '\nNessus found the following nameservers configured in ' + nameserver_file + ' :\n\n' + report;
  security_note(port:0, extra:report);
}
else security_note(0);


#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38831);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/07 20:46:53 $");

  script_cve_id("CVE-2009-1252");
  script_bugtraq_id(35017);
  script_osvdb_id(54576);
  script_xref(name:"CERT", value:"853097");
  script_xref(name:"Secunia", value:"35130");

  script_name(english:"Network Time Protocol Daemon (ntpd) 4.x < 4.2.4p7 / 4.x < 4.2.5p74 crypto_recv() Function RCE");
  script_summary(english:"Checks the remote ntpd version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the remote NTP server is 4.x prior to 4.2.4p7 or 4.x
prior to 4.2.5p74. It is, therefore, affected by a stack-based buffer
overflow condition due to the use of sprintf() in the crypto_recv()
function in ntpd/ntp_crypto.c. An unauthenticated, remote attacker can
exploit this to cause a denial of service condition or the execution
of arbitrary code.

Note that this issue is exploitable only if ntpd was compiled with
OpenSSL support and autokey authentication is enabled. The presence of
the following line in ntp.conf indicates a vulnerable system :

  crypto pw *password*

Nessus did not check if the system is configured in this manner.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.ntp.org/show_bug.cgi?id=1151");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NTP version 4.2.4p7 / 4.2.5p74 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("ntp_open.nasl");
  script_require_keys("NTP/Running", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Make sure NTP server is running
get_kb_item_or_exit('NTP/Running');

app_name = "NTP Server";
port = get_kb_item("Services/udp/ntp");
if (empty_or_null(port)) port = 123;

version = get_kb_item_or_exit("Services/ntp/version");
if (version == 'unknown') audit(AUDIT_UNKNOWN_APP_VER, app_name);

match = eregmatch(string:version, pattern:"([0-9a-z.]+)");
if (isnull(match) || empty_or_null(match[1])) audit(AUDIT_UNKNOWN_APP_VER, app_name);

# Paranoia check
if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = match[1];
verfields = split(ver, sep:".", keep:FALSE);
major = int(verfields[0]);
minor = int(verfields[1]);
if ('p' >< verfields[2])
{
  revpatch = split(verfields[2], sep:"p", keep:FALSE);
  rev = int(revpatch[0]);
  patch = int(revpatch[1]);
}
else
{
  rev = verfields[2];
  patch = 0;
}
fix = '4.2.4p7 / 4.2.5p74';

# This vulnerability affects NTP 4.x < 4.2.5p74 and < 4.2.4p7
if (
    (major == 4 && minor == 2 && rev == 5 && patch < 74) ||
    (major == 4 && minor == 2 && rev == 4 && patch < 7) ||
    (major == 4 && (minor < 2 || (minor == 2 && rev < 4)))
)
{
  fix = '4.2.4p7 / 4.2.5p74';
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

report =
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix +
  '\n';

security_report_v4(
  port  : port,
  proto : "udp",
  extra : report,
  severity : SECURITY_WARNING
);
exit(0);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81981);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/07 20:46:53 $");

  script_cve_id(
    "CVE-2014-9293",
    "CVE-2014-9294",
    "CVE-2014-9295",
    "CVE-2014-9296",
    "CVE-2014-9750",
    "CVE-2014-9751"
  );
  script_bugtraq_id(
    71757,
    71758,
    71761,
    71762,
    72583,
    72584
  );
  script_osvdb_id(
    116066,
    116067,
    116068,
    116069,
    116070,
    116071,
    116072,
    116074
  );
  script_xref(name:"CERT", value:"852879");

  script_name(english:"Network Time Protocol Daemon (ntpd) 4.x < 4.2.8p1 Multiple Vulnerabilities");
  script_summary(english:"Checks for a vulnerable NTP server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the remote NTP server is 4.x prior to 4.2.8p1. It is,
therefore, affected by the following vulnerabilities :

  - A security weakness exists due to the config_auth()
    function improperly generating default keys when no
    authentication key is defined in the ntp.conf file.
    Key size is limited to 31 bits and the insecure
    ntp_random() function is used, resulting in
    cryptographically-weak keys with insufficient entropy. A
    remote attacker can exploit this to defeat cryptographic
    protection mechanisms via a brute-force attack.
    (CVE-2014-9293)

  - A security weakness exists due the use of a weak seed to
    prepare a random number generator used to generate
    symmetric keys. This allows a remote attacker to defeat
    cryptographic protection mechanisms via a brute-force
    attack. (CVE-2014-9294)

  - Multiple stack-based buffer overflow conditions exist
    due to improper validation of user-supplied input when
    handling packets in the crypto_recv(), ctl_putdata(),
    and configure() functions when using autokey
    authentication. A remote attacker can exploit this, via
    a specially crafted packet, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2014-9295)

  - A unspecified vulnerability exists due to missing return
    statements in the receive() function, resulting in 
    continued processing even when an authentication error
    is encountered. This allows a remote attacker, via
    specially crafted packets, to trigger unintended
    association changes. (CVE-2014-9296)

  - An information disclosure vulnerability exists due to
    improper validation of the 'vallen' value in extension
    fields in ntp_crypto.c. A remote attacker can exploit
    this to disclose sensitive information. (CVE-2014-9750)

  - A security bypass vulnerability exists due to a failure
    to restrict ::1 source addresses on IPv6 interfaces. A
    remote attacker can exploit this to bypass configured
    ACLs based on ::1. (CVE-2014-9751)

Note that CVE-2014-9750 and CVE-2014-9751 supersede the discontinued
identifiers CVE-2014-9297 and CVE-2014-9298, which were originally
cited in the vendor advisory.");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/SecurityNotice");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NTP version 4.2.8p1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
if (!port) port = 123;

version = get_kb_item_or_exit("Services/ntp/version");
if (version == 'unknown') audit(AUDIT_UNKNOWN_APP_VER, app_name);

match = eregmatch(string:version, pattern:"([0-9a-z.]*)");
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

# This vulnerability affects NTP 4.x < 4.2.8p1
if (
  (major == 4 && minor < 2) ||
  (major == 4 && minor == 2 && rev < 8) ||
  (major == 4 && minor == 2 && rev == 8 && patch < 1)
)
{
  fix = "4.2.8p1";
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
  severity : SECURITY_HOLE
);
exit(0);

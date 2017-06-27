#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86631);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/07 20:46:53 $");

  script_cve_id(
    "CVE-2015-7691",
    "CVE-2015-7692",
    "CVE-2015-7701",
    "CVE-2015-7702",
    "CVE-2015-7703",
    "CVE-2015-7704",
    "CVE-2015-7705",
    "CVE-2015-7848",
    "CVE-2015-7849",
    "CVE-2015-7850",
    "CVE-2015-7851",
    "CVE-2015-7852",
    "CVE-2015-7853",
    "CVE-2015-7854",
    "CVE-2015-7855",
    "CVE-2015-7871"
  );
  script_bugtraq_id(
    77273,
    77274,
    77275,
    77276,
    77277,
    77278,
    77279,
    77280,
    77281,
    77282,
    77283,
    77284,
    77285,
    77286,
    77287,
    77288
  );
  script_osvdb_id(
    116071,
    126666,
    129298,
    129299,
    129300,
    129301,
    129302,
    129303,
    129304,
    129305,
    129306,
    129307,
    129309,
    129310,
    129311
  );
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"Network Time Protocol Daemon (ntpd) 3.x / 4.x < 4.2.8p4 Multiple Vulnerabilities");
  script_summary(english:"Checks for a vulnerable NTP server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the remote NTP server is 3.x or 4.x prior to 4.2.8p4.
It is, therefore, affected by the following vulnerabilities :

  - A flaw exists in the ntp_crypto.c file due to improper
    validation of the 'vallen' value in extension fields. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted autokey packets, to disclose
    sensitive information or cause a denial of service.
    (CVE-2015-7691)

  - A denial of service vulnerability exists in the autokey
    functionality due to a failure in the crypto_bob2(),
    crypto_bob3(), and cert_sign() functions to properly
    validate the 'vallen' value. An unauthenticated, remote
    attacker can exploit this, via specially crafted autokey
    packets, to crash the NTP service. (CVE-2015-7692)

  - A denial of service vulnerability exists in the
    crypto_recv() function in the file ntp_crypto.c related
    to autokey functionality. An unauthenticated, remote
    attacker can exploit this, via an ongoing flood of NTPv4
    autokey requests, to exhaust memory resources.
    (CVE-2015-7701)

  - A denial of service vulnerability exists due to improper
    validation of packets containing certain autokey
    operations. An unauthenticated, remote attacker can
    exploit this, via specially crafted autokey packets,
    to crash the NTP service. (CVE-2015-7702)

  - A flaw exists related to the handling of the 'config:'
    command. An authenticated, remote attacker can exploit
    this to set the 'pidfile' and 'driftfile' directives
    without restrictions, thus allowing the attacker to
    overwrite arbitrary files. Note that exploitation of
    this issue requires that remote configuration is enabled
    for ntpd. (CVE-2015-7703)

  - A denial of service vulnerability exists due improper
    validation of the origin timestamp when handling
    Kiss-of-Death (KoD) packets. An unauthenticated, remote
    attacker can exploit this to stop the client from
    querying its servers, preventing it from updating its
    clock. (CVE-2015-7704)

  - A denial of service vulnerability exists due to improper
    implementation of rate-limiting when handling server
    queries. An unauthenticated, remote attacker can exploit
    this to stop the client from querying its servers,
    preventing it from updating its clock. (CVE-2015-7705)

  - A denial of service vulnerability exists due to an
    integer overflow condition in the reset_peer() function
    in the file ntp_request.c when handling private mode
    packets having request code RESET_PEER (0x16). An
    authenticated, remote attacker can exploit this to crash
    the NTP service. Note that exploitation of this issue
    requires that ntpd is configured to enable mode 7
    packets, and that the mode 7 packets are not properly
    protected by available authentication and restriction
    mechanisms. (CVE-2015-7848)

  - A use-after-free error exists in the auth_delkeys()
    function in the file authkeys.c when handling trusted
    keys. An authenticated, remote attacker can exploit this
    to dereference already freed memory, resulting in a
    crash of the NTP service or the execution of arbitrary
    code. (CVE-2015-7849)

  - A denial of service vulnerability exists due to a logic
    flaw in the authreadkeys() function in the file
    authreadkeys.c when handling extended logging where the
    log and key files are set to be the same file. An
    authenticated, remote attacker can exploit this, via a
    crafted set of remote configuration requests, to cause
    the NTP service to stop responding. (CVE-2015-7850)

  - A flaw exists in the save_config() function in the file
    ntp_control.c due to improper sanitization of
    user-supplied input. An authenticated, remote attacker
    can exploit this issue, via a crafted set of
    configuration requests, to overwrite arbitrary files.
    Note that this issue only affects VMS systems and
    requires that ntpd is configured to allow remote
    configuration. (CVE-2015-7851)

  - A denial of service vulnerability exists due to an
    off-by-one overflow condition in the cookedprint()
    function in the file ntpq.c when handling mode 6
    response packets. An unauthenticated, remote attacker
    can exploit this to crash the NTP service.
    (CVE-2015-7852)

  - A overflow condition exists in the
    read_refclock_packet() function in the file ntp_io.c
    when handling negative data lengths. A local attacker
    can exploit this to crash the NTP service or possibly
    gain elevated privileges. (CVE-2015-7853)

  - A heap-based overflow condition exists in function
    MD5auth_setkey() in the file authkeys.c when handling
    passwords. An authenticated, remote attacker can exploit
    this, via a crafted set of configuration requests, to
    crash the NTP service or possibly execute arbitrary
    code. (CVE-2015-7854)

  - A denial of service vulnerability exists due to an
    assertion flaw in the decodenetnum() function in the
    file decodenetnum.c when handling long data values in
    mode 6 and 7 packets. An unauthenticated, remote
    attacker can exploit this to crash the NTP service.
    (CVE-2015-7855)

  - An authentication bypass vulnerability exists in the
    receive() function in the file ntp_proto.c when handling
    crypto-NAK packets. An unauthenticated, remote attacker
    can exploit this to cause the service to accept time
    from unauthenticated, ephemeral symmetric peers.
    (CVE-2015-7871)");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/research/tra-2015-04");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/SecurityNotice");
  # http://support.ntp.org/bin/view/Main/SecurityNotice#October_2015_NTP_Security_Vulner
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08d2ada0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NTP version 4.2.8p4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/28");

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

# This vulnerability affects NTP 3.x / 4.x < 4.2.8p4
if (
  (major < 4 && major >= 3) ||
  (major == 4 && minor < 2) ||
  (major == 4 && minor == 2 && rev < 8) ||
  (major == 4 && minor == 2 && rev == 8 && patch < 4)
)
{
  fix = "4.2.8p4";
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

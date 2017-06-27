#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83744);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/07 20:46:53 $");

  script_cve_id(
    "CVE-2015-1798",
    "CVE-2015-1799",
    "CVE-2015-3405"
  );
  script_bugtraq_id(
    73950,
    73951,
    74045
  );
  script_osvdb_id(
    120350,
    120351,
    120524
  );
  script_xref(name:"CERT", value:"374268");

  script_name(english:"Network Time Protocol Daemon (ntpd) 3.x / 4.x < 4.2.8p2 Multiple Vulnerabilities");
  script_summary(english:"Checks for a vulnerable NTP server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the remote NTP server is 3.x or 4.x prior to 4.2.8p2.
It is, therefore, affected by the following vulnerabilities :

  - The symmetric-key feature in the receive() function
    requires a correct message authentication code (MAC)
    only if the MAC field has a nonzero length. A
    man-in-the-middle attacker can exploit this to spoof
    packets by omitting the MAC. (CVE-2015-1798)

  - A flaw exists in the symmetric-key feature in the
    receive() function when handling a specially crafted
    packet sent to one of two hosts that are peering with
    each other. An attacker can exploit this to cause the
    next attempt by the servers to synchronize to fail.
    (CVE-2015-1799)

  - A flaw exists in util/ntp-keygen.c due to the way that
    the ntp-keygen utility generates MD5 symmetric keys on
    big-endian systems. A remote attacker can exploit this
    to more easily guess MD5 symmetric keys and thereby
    spoof an NTP server or client. (CVE-2015-3405)");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/SecurityNotice");
  # http://support.ntp.org/bin/view/Main/SecurityNotice#April_2015_NTP_Security_Vulnerab
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9fd24f37");
  script_set_attribute(attribute:"see_also", value:"http://bugs.ntp.org/show_bug.cgi?id=2797");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NTP version 4.2.8p2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/21");

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

# This vulnerability affects NTP 3.x / 4.x < 4.2.8p2
if (
  (major < 4 && major >= 3) ||
  (major == 4 && minor < 2) ||
  (major == 4 && minor == 2 && rev < 8) ||
  (major == 4 && minor == 2 && rev == 8 && patch < 2)
)
{
  fix = "4.2.8p2";
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

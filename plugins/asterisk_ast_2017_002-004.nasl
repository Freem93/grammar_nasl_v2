#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100386);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/25 13:56:51 $");

  script_osvdb_id(
    157966,
    157967,
    157973
  );
  script_xref(name:"IAVA", value:"2017-A-0153");

  script_name(english:"Asterisk 13.13 < 13.13-cert4 / 13.x < 13.15.1 / 14.x < 14.4.1 Multiple Vulnerabilities (AST-2017-002 - AST-2017-004)");
  script_summary(english:"Checks the version in the SIP banner.");

  script_set_attribute(attribute:"synopsis", value:
"A telephony application running on the remote host is affected by 
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its SIP banner, the version of Asterisk running on the
remote host is 13.13 prior to 13.13-cert4, 13.x prior to 13.15.1, or
14.x prior to 14.4.1. Is it, therefore, affected by multiple
vulnerabilities :

  - An out-of-bounds read error exists in the multi-part
    body parser in PJSIP due to reading memory outside the
    allowed boundaries. An unauthenticated, remote attacker
    can exploit this, via specially crafted packets, to
    trigger an invalid read, resulting in a denial of
    service condition. (VulnDB 157966)

  - A denial of service vulnerability exists in 'partial
    data' message logging when handling SCCP packets that
    have 'chan_skinny' enabled and that are larger than the
    length of the SCCP header but smaller than the packet
    length specified in the header. The loop that reads the
    rest of the packet fails to detect that the call to
    read() returned end-of-file before the expected number
    of bytes and therefore continues indefinitely. An
    unauthenticated, remote attacker can exploit this issue,
    via specially crafted packets, to exhaust all available
    memory. (VulnDB 157967)

  - A denial of service vulnerability exists in the PJSIP
    RFC 2543 transaction key generation algorithm due to a
    failure to allocate a sufficiently large buffer when
    handling a SIP packet with a specially crafted CSeq
    header and a Via header with no branch parameter.
    An unauthenticated, remote attacker can exploit this,
    via specially crafted packets, to overflow the buffer,
    resulting in memory corruption and an eventual crash.
    (VulnDB 157973)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2017-002.html");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2017-003.html");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2017-004.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Asterisk version 13.13-cert4 / 13.15.1 / 14.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:digium:asterisk");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("asterisk_detection.nasl");
  script_require_keys("asterisk/sip_detected", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("asterisk/sip_detected");

asterisk_kbs = get_kb_list_or_exit("sip/asterisk/*/version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

is_vuln = FALSE;
not_vuln_installs = make_list();
errors = make_list();

foreach kb_name (keys(asterisk_kbs))
{
  vulnerable = 0;

  matches = eregmatch(pattern:"/(udp|tcp)/([0-9]+)/version", string:kb_name);
  if (isnull(matches))
  {
    errors = make_list(errors, "Unexpected error parsing port number from '"+kb_name+"'.");
    continue;
  }

  proto = matches[1];
  port  = matches[2];
  version = asterisk_kbs[kb_name];

  if (version == 'unknown')
  {
    errors = make_list(errors, "Unable to obtain version of installation on " + proto + "/" + port + ".");
    continue;
  }

  banner = get_kb_item("sip/asterisk/" + proto + "/" + port + "/source");
  if (!banner)
  {
    # We have version but banner is missing;
    # log error and use in version-check though.
    errors = make_list(errors, "KB item 'sip/asterisk/" + proto + "/" + port + "/source' is missing.");
    banner = 'unknown';
  }

  if (version =~ "^13([^0-9])" && "cert" >!< tolower(version))
  {
    fixed = "13.15.1";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }
  else if (version =~ "^14([^0-9])" && "cert" >!< tolower(version))
  {
    fixed = "14.4.1";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }
  else if (version =~ "^13\.13([^0-9])" && "cert" >< tolower(version))
  {
    fixed = "13.13-cert4";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  if (vulnerable < 0)
  {
    is_vuln = TRUE;
    report =
        '\n  Version source    : ' + banner +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed +
        '\n';
      security_report_v4(severity:SECURITY_HOLE, port:port, proto:proto, extra:report);
  }
  else not_vuln_installs = make_list(not_vuln_installs, version + " on port " + proto + "/" + port);
}

if (max_index(errors))
{
  if (max_index(errors) == 1) errmsg = errors[0];
  else errmsg = 'Errors were encountered verifying installations : \n  ' + join(errors, sep:'\n  ');

  exit(1, errmsg);
}
else
{
  installs = max_index(not_vuln_installs);
  if (installs == 0)
  {
    if (is_vuln) exit(0);
    else audit(AUDIT_NOT_INST, "Asterisk");
  }
  else audit(AUDIT_INST_VER_NOT_VULN, "Asterisk", not_vuln_installs);
}

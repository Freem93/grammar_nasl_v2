#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82901);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/11 20:08:41 $");

  script_cve_id("CVE-2015-3008");
  script_bugtraq_id(74022);
  script_osvdb_id(120492);

  script_name(english:"Asterisk TLS Certificate Common Name NULL Byte Vulnerability (AST-2015-003)");
  script_summary(english:"Checks the version in the SIP banner.");

  script_set_attribute(attribute:"synopsis", value:
"A telephony application running on the remote host is affected by a
certificate validation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its SIP banner, the version of Asterisk running on the
remote host is potentially affected by flaw related to certificate
validation when registering a SIP TLS device due to not properly
verifying a server hostname against an X.509 Common Name (CN) field
that has a NULL byte appended after the expected results. A
man-in-the-middle attacker can exploit this, via a crafted
certificate, to spoof arbitrary SSL servers and intercept network
traffic.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Asterisk 1.8.32.3 / 11.17.1 / 12.8.2 / 13.3.2 /
1.8.28-cert5 / 11.6-cert11 / 13.1-cert2, or apply the appropriate
patch listed in the Asterisk advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2015-003.html");
  script_set_attribute(attribute:"see_also", value:"https://issues.asterisk.org/jira/browse/ASTERISK-24847");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:digium:asterisk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
    errors = make_list(errors, "Unable to obtain version of install on " + proto + "/" + port + ".");
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

  # Open Source 1.8.x < 1.8.32.3
  if (version =~ "^1\.8([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "1.8.32.3";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Open Source 11.x < 11.17.1
  if (version =~ "^11([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "11.17.1";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Open Source 12.x < 12.8.2
  else if (version =~ "^12([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "12.8.2";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Open Source 13.x < 13.3.2
  else if (version =~ "^13([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "13.3.2";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Asterisk Certified 1.8.28-certx < 1.8.28-cert5
  else if (version =~ "^1\.8\.28([^0-9])" && "cert" >< tolower(version))
  {
    fixed = "1.8.28-cert5";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Asterisk Certified 11.6-certx < 11.6-cert11
  else if (version =~ "^11\.6([^0-9])" && "cert" >< tolower(version))
  {
    fixed = "11.6-cert11";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Asterisk Certified 13.1-certx < 13.1-cert2
  else if (version =~ "^13\.1([^0-9])" && "cert" >< tolower(version))
  {
    fixed = "13.1-cert2";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  if (vulnerable < 0)
  {
    is_vuln = TRUE;
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + banner +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed +
        '\n';
      security_warning(port:port, proto:proto, extra:report);
    }
    else security_warning(port:port, proto:proto);
  }
  else not_vuln_installs = make_list(not_vuln_installs, version + " on port " + proto + "/" + port);
}

if (max_index(errors))
{
  if (max_index(errors) == 1) errmsg = errors[0];
  else errmsg = 'Errors were encountered verifying installs : \n  ' + join(errors, sep:'\n  ');

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

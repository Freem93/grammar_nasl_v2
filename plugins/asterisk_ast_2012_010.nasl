#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60064);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_cve_id("CVE-2012-3863");
  script_bugtraq_id(54327);
  script_osvdb_id(83670);

  script_name(english:"Asterisk Endpoint Provisional Response Parsing RTP Port Consumption Remote DoS (AST-2012-010)");
  script_summary(english:"Checks version in SIP banner");

  script_set_attribute(attribute:"synopsis", value:
"A telephony application running on the remote host is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the version in its SIP banner, the version of Asterisk
running on the remote host is potentially affected by a vulnerability
that could allow a remote, authenticated attacker to exhaust the
server of resources.

If an endpoint sends a provisional response to the server's re-INVITE
message, certain data structures are not freed. More iterations of
this sequence lead to exhaustion of all available RTP ports.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Asterisk Open Source 1.8.13.1 / 10.5.2, Business Edition
C.3.7.5, Certified Asterisk 1.8.11-cert4 or apply the patches listed in
the Asterisk advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2012-010.html");
  script_set_attribute(attribute:"see_also", value:"https://issues.asterisk.org/jira/browse/ASTERISK-19992");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:digium:asterisk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("asterisk_detection.nasl");
  script_require_keys("asterisk/sip_detected", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("asterisk/sip_detected");

# see if we were able to get version info from the Asterisk SIP services
asterisk_kbs = get_kb_list("sip/asterisk/*/version");
if (isnull(asterisk_kbs)) exit(1, "Could not obtain any version information from the Asterisk SIP instance(s).");

# Prevent potential false positives.
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
    errors = make_list(errors, "Unexpected error parsing port number from kb name: "+kb_name);
    continue;
  }

  proto = matches[1];
  port  = matches[2];
  version = asterisk_kbs[kb_name];

  if (version == 'unknown')
  {
    errors = make_list(errors, "Unable to obtain version of install on " + proto + "/" + port);
    continue;
  }

  banner = get_kb_item("sip/asterisk/" + proto + "/" + port + "/source");
  if (!banner)
  {
    # We have version but banner is missing; log error
    # and use in version-check though.
    errors = make_list(errors, "KB item 'sip/asterisk/" + proto + "/" + port + "/source' is missing");
    banner = 'unknown';
  }

  # Open Source 10x < 10.5.2
  if (version =~ "^10([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "10.5.2";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Open Source 1.8.x < 1.8.13.1
  if (version =~ "^1\.8([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "1.8.13.1";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Business Edition C.3.x < C.3.7.5
  if (version =~ "^C\.3\.([0-6]|7\.[0-4])([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "C.3.7.5";
    vulnerable = -1;
  }

  # Asterisk Certified 1.8.11-certx < 1.8.11-cert4
  if (version =~ "^1\.8\.11([^0-9]|$)" && "cert" >< tolower(version))
  {
    fixed = "1.8.11-cert4";
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
        '\n  Fixed version     : ' + fixed + '\n';
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
    if (is_vuln)
      exit(0);
    else
      audit(AUDIT_NOT_INST, "Asterisk");
  }
  else if (installs == 1) audit(AUDIT_INST_VER_NOT_VULN, "Asterisk " + not_vuln_installs[0]);
  else exit(0, "The Asterisk installs (" + join(not_vuln_installs, sep:", ") + ") are not affected.");
}

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53544);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/09/21 19:09:13 $");

  script_cve_id("CVE-2011-1507", "CVE-2011-1599");
  script_bugtraq_id(47537);
  script_osvdb_id(73433, 73434);
  script_xref(name:"Secunia", value:"44197");

  script_name(english:"Asterisk Multiple Vulnerabilities (AST-2011-005 / AST-2011-006)");
  script_summary(english:"Checks version in SIP banner");

  script_set_attribute(attribute:"synopsis", value:
"A telephony application running on the remote host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the version in its SIP banner, the version of Asterisk
running on the remote host may be affected by multiple denial of
service vulnerabilities :

  - On systems that have the Asterisk Manager interface,
    Skinny, SIP over TCP, or the built-in HTTP server
    enabled, it is possible for an attacker to open an
    unlimited number of connections to Asterisk, which would
    cause Asterisk to run out of available file descriptors
    and stop processing any new calls. (AST-2011-005)

  - It is possible to bypass a security check and execute
    shell commands when they should not have that ability.
    Note that only users with the 'system' privilege should
    be able to do this. (AST-2011-006)");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2011-005.html");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2011-006.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Asterisk 1.4.40.1 / 1.6.1.25 / 1.6.2.17.3 / 1.8.3.3 /
Business Edition C.3.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:digium:asterisk");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

  if (version =~ '^1\\.4([^0-9]|$)')
  {
    fixed = '1.4.40.1';
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }
  else if (version =~ '^1\\.6([^0-9]|$)')
  {
    if (version =~ '^1\\.6\\.1([^0-9]|$)')
    {
      fixed = "1.6.1.25";
      vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
    }
    else if (version =~ '^1\\.6\\.2([^0-9]|$)')
    {
      fixed = "1.6.2.17.3";
      if (version =~ '^1\\.6\\.2\\.17([^0-9]|$)')
        vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
      else
        vulnerable = ver_compare(ver:version, fix:"1.6.2.17", app:"asterisk");
    }
  }
  else if (version =~ '^1\\.8([^0-9]|$)')
  {
    fixed = "1.8.3.3";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }
  else if (version =~ '^[A-Z]')
  {
    fixed = 'C.3.6.4';
    if (version[0] <= 'B')
    {
      vulnerable = -1;
    }
    else if (version[0] > 'C')
    {
      vulnerable = 1;
    }
    else
    {
      tmp_fixed = substr(fixed, 2);
      tmp_version = substr(version, 2);
      vulnerable = ver_compare(ver:tmp_version, fix:tmp_fixed, app:"asterisk");
    }
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

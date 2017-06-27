#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52714);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/09/21 19:09:13 $");

  script_cve_id("CVE-2011-1174", "CVE-2011-1175");
  script_bugtraq_id(46897, 46898);
  script_osvdb_id(73405, 73406);
  script_xref(name:"Secunia", value:"43722");

  script_name(english:"Asterisk Multiple Denial of Service Vulnerabilities (AST-2011-003 / AST-2011-004)");
  script_summary(english:"Checks version in SIP banner");

  script_set_attribute(attribute:"synopsis", value:
"A telephony application running on the remote host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the version in its SIP banner, the version of Asterisk
running on the remote host may be affected by multiple denial of
service vulnerabilities :

  - A resource exhaustion issue exists in the Asterisk
    manager interface.

  - A NULL pointer dereference issue exists in the
    TCP/TLS server.");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2011-003.html");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2011-004.html");
  # http://web.archive.org/web/20110823054112/http://www.asterisk.org/node/51596
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ecf62e4");
  script_set_attribute(attribute:"solution", value:"Upgrade to Asterisk 1.6.1.24 / 1.6.2.17.2 / 1.8.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/18");

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

  if (version =~ '^1\\.6([^0-9]|$)')
  {
    if (version =~ '^1\\.6\\.1([^0-9]|$)')
    {
      fixed = "1.6.1.24";
      vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
    }
    else if (version =~ '^1\\.6\\.2([^0-9]|$)')
    {
      fixed = "1.6.2.17.2";
      if (version =~ '^1\\.6\\.2\\.17([^0-9]|$)')
        vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
      else
        vulnerable = ver_compare(ver:version, fix:"1.6.2.17", app:"asterisk");
    }
  }
  else if (version =~ '^1\\.8([^0-9]|$)')
  {
    fixed = "1.8.3.2";
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

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76088);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_cve_id("CVE-2014-4047");
  # script_bugtraq_id();
  script_osvdb_id(108084);

  script_name(english:"Asterisk HTTP Session Handling DoS (AST-2014-007)");
  script_summary(english:"Checks version in SIP banner.");

  script_set_attribute(attribute:"synopsis", value:
"A telephony application running on the remote host is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the version in its SIP banner, the version of Asterisk
running on the remote host is potentially affected by a denial of
service vulnerability. A flaw exists in the handling of TCP and TLS
connections when the connection is initiated but not completed. A
remote attacker could repeatedly send such requests that may result in
a denial of service.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Asterisk 1.8.28.1 / 11.10.1 / 12.3.1 / Certified Asterisk
1.8.15-cert6 / 11.6-cert3, or apply the appropriate patch listed in
the Asterisk advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2014-007.html");
  # http://asterisktimes.xdev.net/2014/06/13/asterisk-1-8-15-cert7-1-8-28-2-11-6-cert4-11-10-2-12-3-2-now-available-securityregression-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d949b72e");
  script_set_attribute(attribute:"see_also", value:"https://issues.asterisk.org/jira/browse/ASTERISK-23673");
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.28.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95c079df");
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-11.10.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd99d03c");
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-12.3.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12bda26e");
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-1.8.15-cert6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98e4995b");
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-11.6-cert3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d60d352");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:digium:asterisk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

  # Open Source 1.8.x < 1.8.28.1
  if (version =~ "^1\.8([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "1.8.28.1";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Open Source 11.x < 11.10.1
  if (version =~ "^11([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "11.10.1";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Open Source 12.x < 12.3.1
  if (version =~ "^12\." && "cert" >!< tolower(version))
  {
    fixed = "12.3.1";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Asterisk Certified 1.8.15-certx < 1.8.15-cert6
  if (version =~ "^1\.8\.15([^0-9])" && "cert" >< tolower(version))
  {
    fixed = "1.8.15-cert6";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Asterisk Certified 11.6-certx < 11.6-cert3
  if (version =~ "^11\.6([^0-9])" && "cert" >< tolower(version))
  {
    fixed = "11.6-cert3";
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

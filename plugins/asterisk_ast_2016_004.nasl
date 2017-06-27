#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90799);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/16 21:23:29 $");

  script_osvdb_id(137214);

  script_name(english:"Asterisk REGISTER Request Contact URI Handling DoS (AST-2016-004)");
  script_summary(english:"Checks the version in the SIP banner.");

  script_set_attribute(attribute:"synopsis", value:
"A telephony application running on the remote host is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its SIP banner, the version of Asterisk running on the
remote host is either 13.x prior to 13.8.1 or 13.1-cert prior to
13.1-cert5. It is, therefore, affected by a flaw when processing
incoming REGISTER requests if the REGISTER contains an overlong URI
in the Contact header. An authenticated, remote attacker can exploit
this to cause a denial of service condition.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Asterisk version 13.8.1 / 13.1-cert5, or apply the
appropriate patch according to the Asterisk advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2016-004.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2016/Apr/85");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:digium:asterisk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

  # Open Source 13.x < 13.8.1
  if (version =~ "^13([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "13.8.1";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Asterisk Certified 13.1-certx < 13.1-cert5
  else if (version =~ "^13\.1([^0-9])" && "cert" >< tolower(version))
  {
    fixed = "13.1-cert5";
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
      security_report_v4(severity:SECURITY_WARNING, port:port, proto:proto, extra:report);
  }
  else not_vuln_installs = make_list(not_vuln_installs, version + " on port " + proto + "/" + port);
}

if (max_index(errors))
{
  if (max_index(errors) == 1) errmsg = errors[0];
  else errmsg = 'Errors were encountered verifying installation : \n  ' + join(errors, sep:'\n  ');

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

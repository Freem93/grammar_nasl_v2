#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57289);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_cve_id("CVE-2011-4597", "CVE-2011-4598");
  script_bugtraq_id(50989, 50990);
  script_osvdb_id(77597, 77598);

  script_name(english:"Asterisk Multiple Vulnerabilities (AST-2011-013 / AST-2011-014)");
  script_summary(english:"Checks version in SIP banner.");

  script_set_attribute(attribute:"synopsis", value:
"A telephony application running on the remote host is affected by 
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the version in its SIP banner, the version of Asterisk
running on the remote host is potentially affected by the following
vulnerabilities :

  - An issue in the SIP protocol can lead to the enumeration
    of endpoints with NAT settings different from the
    default. Note that this is an issue with the SIP
    protocol itself, and that updated versions of Asterisk
    provide warnings and safer defaults. (AST-2011-013)

  - A NULL pointer derefererence can lead to an application
    crash by a remote, unauthenticated user when processing
    a SIP request. Note that successful exploitation
    requires that the 'automon' feature in features.conf be
    enabled and that it is not by default. (AST-2011-014)");

  script_set_attribute(attribute:"solution", value:
"Either update to Asterisk 1.6.2.21 / 1.8.7.2 or later or disable the
'automon' feature in features.conf.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value: "http://downloads.asterisk.org/pub/security/AST-2011-013.html");
  script_set_attribute(attribute:"see_also", value: "http://downloads.asterisk.org/pub/security/AST-2011-014.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:digium:asterisk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

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

  if (version =~ "^1\.6([^0-9]|$)")
  {
   fixed = "1.6.2.21";
   vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }
  else if (version =~ "^1\.8([^0-9]|$)")
  {
    fixed = "1.8.7.2";
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

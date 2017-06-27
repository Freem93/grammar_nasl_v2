#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65896);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_cve_id("CVE-2013-2685");
  script_bugtraq_id(58760);
  script_osvdb_id(91753);

  script_name(english:"Asterisk SIP SDP Buffer Overflow (AST-2013-001)");
  script_summary(english:"Checks version in SIP banner");

  script_set_attribute(attribute:"synopsis", value:
"A telephony application running on the remote host is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the version in its SIP banner, the version of Asterisk
running on the remote host is potentially affected by a buffer overflow
vulnerability related to SIP SDP headers and h264 video handling.  This
error could allow execution of arbitrary code.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Asterisk 11.2.2 or apply the patch listed in the Asterisk
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2013-001.html");
  script_set_attribute(attribute:"see_also", value:"https://issues.asterisk.org/jira/browse/ASTERISK-20901");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:digium:asterisk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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
    # We have version but banner is missing; log error
    # and use in version-check though.
    errors = make_list(errors, "KB item 'sip/asterisk/" + proto + "/" + port + "/source' is missing.");
    banner = 'unknown';
  }

  # Open Source 11x < 11.2.2
  if (version =~ "^11\.([01]|2\.[01])([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "11.2.2";
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
      security_hole(port:port, proto:proto, extra:report);
    }
    else security_hole(port:port, proto:proto);
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

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63203);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_bugtraq_id(55599);

  script_name(english:"FreeSWITCH Route Header Value Handling DoS");
  script_summary(english:"Checks the version of FreeSWITCH.");

  script_set_attribute(attribute:"synopsis", value:
"The remote SIP service is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote FreeSWITCH install
is affected by a denial of service vulnerability in the Sofia SIP
stack. A remote attacker can exploit this, via a specially crafted
INVITE request with a 'Route' value containing a long list, to crash
the service.");
  script_set_attribute(attribute:"see_also", value:"https://freeswitch.org/jira/browse/FS-4627");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FreeSWITCH version 1.3.0 commit
016550f218fb0ea54aa6163d6a6eb7e02539da5e or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:freeswitch:freeswitch");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("freeswitch_detection.nbin");
  script_require_keys("Settings/ParanoidReport", "sip/freeswitch/present");
  script_require_ports("Services/udp/sip", "Services/sip");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "FreeSWITCH";
get_kb_item_or_exit("sip/freeswitch/present");

# Prevent potential false positives.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

errors = make_list();
udp_ports = get_kb_list("Services/udp/sip");
tcp_ports = get_kb_list("Services/sip");
if (isnull(tcp_ports) && isnull(udp_ports)) audit(AUDIT_NOT_INST, appname);

function check_banner(version, timestamphi, timestamplo, port, proto)
{
  local_var report = '';
  if (version == 'unknown')
  {
    errors = make_list(errors, "Unable to determine the FreeSWITCH version on " + proto + "/" + port + ".");
    return FALSE;
  }

  # fix is in 1.3.0 branch, so versions < 1.3.0 are vuln
  if (ver_compare(ver:version, fix:"1.3.0", strict:FALSE) == -1)
  {
    report =
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 1.3.0 commit 016550f\n';
  }   
  # fix is in GIT with version 1.3.0
  else if (version == "1.3.0") {
    if (timestamphi && timestamplo)
    {
      # see if we can check git timestamp
      if (timestamphi < 20120918 ||
        (timestamphi == 20120918 && timestamplo < 234200))
      {
        report = 
            '\n  Installed version : ' + version +
            '\n  Fixed version     : 1.3.0 commit 016550f\n';
      }
    } else {
      report =
            '\n Unable to determine commit timestamp. May be vulnerable' +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : 1.3.0 commit 016550f\n';
    }
  }
  if (report != '')
  {
    if (report_verbosity > 0) security_warning(extra:report, port:port, proto:proto);
    else security_warning(port:port, proto:proto);
    return TRUE;
  }
  return FALSE;
}

is_vuln = FALSE;
if (!isnull(tcp_ports))
{
  foreach port (make_list(tcp_ports))
  {
    version = get_kb_item("sip/freeswitch/tcp/" + port + "/version");
    if (!version) continue;
    timestamphi = get_kb_item("sip/freeswitch/tcp/" + port + "/gittimestamphi");
    timestamplo = get_kb_item("sip/freeswitch/tcp/" + port + "/gittimestamplo");
    if (check_banner(version:version, timestamphi:timestamphi,
      timestamplo:timestamplo, proto:"tcp", port:port)) is_vuln = TRUE;
  }
}
if (!isnull(udp_ports))
{
  foreach port (make_list(udp_ports))
  {
    version = get_kb_item("sip/freeswitch/udp/" + port + "/version");
    if (!version) continue;
    timestamphi = get_kb_item("sip/freeswitch/udp/" + port + "/gittimestamphi");
    timestamplo = get_kb_item("sip/freeswitch/udp/" + port + "/gittimestamplo");
    if (check_banner(version:version, timestamphi:timestamphi,
      timestamplo:timestamplo, proto:"udp", port:port)) is_vuln = TRUE;
  }
}

if (max_index(errors))
{
  errmsg = 'Errors were encountered verifying installs : \n  ' + join(errors, sep:'\n  ');
  exit(1, errmsg);
} else if(!is_vuln) audit(AUDIT_INST_VER_NOT_VULN, appname);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88696);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2015-7392", "CVE-2015-8311");
  script_bugtraq_id(76976);
  script_osvdb_id(128211);
  script_xref(name:"TRA", value:"TRA-2015-05");

  script_name(english:"FreeSWITCH < 1.4.26 / 1.6.x < 1.6.5 JSON Parser RCE");
  script_summary(english:"Checks the version of FreeSWITCH.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeSWITCH server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote FreeSWITCH server is prior to version 1.4.26 or 1.6.x prior
to 1.6.5. It is, therefore, affected by a remote code execution
vulnerability due to improper validation of user-supplied input to the
parse_string() function in esl_json.c, switch_json.c, and ks_json.c. A
remote attacker can exploit this, via a crafted JSON message, to cause
a heap-based buffer overflow condition, resulting in a denial of
service or the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://freeswitch.org/jira/browse/FS-8160");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2015-05");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FreeSWITCH version 1.4.26 / 1.6.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:freeswitch:freeswitch");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

errors = make_list();
udp_ports = get_kb_list("Services/udp/sip");
tcp_ports = get_kb_list("Services/sip");
if (isnull(tcp_ports) && isnull(udp_ports)) audit(AUDIT_NOT_INST, appname);

function is_vulnerable(version, commit, proto, port)
{
  local_var report = '';

  if (version == 'unknown')
  {
    errors = make_list(errors, "Unable to determine the FreeSWITCH version on " + proto + "/" + port + ".");
    return FALSE;
  }

  # the fix was pushed out in 1.6.5
  if (ver_compare(ver:version, fix:"1.6.5", strict:FALSE) < 0)
  {
    # freeswitch now maintains a 1.6 branch and a 1.4 branch. Determine
    # if we are looking at a 1.4 line
    if (ver_compare(ver:version, fix:"1.5", strict:FALSE) < 0)
    {
      if (ver_compare(ver:version, fix:"1.4.26", strict:FALSE) < 0)
      {
        report = 
          '\n  Installed version : ' + version + 
          '\n  Fixed version     : 1.4.26\n';
      }
    }
    else
    {
      report = 
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 1.6.5\n';
    }
  }

  if (report != '')
  {
    if (report_verbosity > 0) security_hole(extra:report, port:port, proto:proto);
    else security_hole(port:port, proto:proto);
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
    if (!isnull(version) && is_vulnerable(version:version, proto:"tcp", port:port)) is_vuln = TRUE;
  }
}
if (!isnull(udp_ports))
{
  foreach port (make_list(udp_ports))
  {
    version = get_kb_item("sip/freeswitch/udp/" + port + "/version");
    if (!version) continue;
    if (!isnull(version) && is_vulnerable(version:version, proto:"udp", port:port)) is_vuln = TRUE;
  }
}

if (max_index(errors))
{
  errmsg = 'Errors were encountered verifying installs : \n  ' + join(errors, sep:'\n  ');
  exit(1, errmsg);
} else if(!is_vuln) audit(AUDIT_INST_VER_NOT_VULN, appname);


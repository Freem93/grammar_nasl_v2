#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95951);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/21 20:09:49 $");

  script_cve_id("CVE-2016-9192");
  script_bugtraq_id(94770);
  script_osvdb_id(148319);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161207-anyconnect1");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb68043");

  script_name(english:"Cisco AnyConnect Secure Mobility Client 3.1.x < 4.3.4019.0 / 4.4.x < 4.4.225.0 Privilege Escalation");
  script_summary(english:"Checks the version of the Cisco AnyConnect client.");

  script_set_attribute(attribute:"synopsis", value:
"A VPN application installed on the remote host is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco AnyConnect Secure Mobility Client installed on
the remote Windows host is 3.x or 4.x prior to 4.3.4019.0 or 4.4.x
prior to 4.4.225.0. It is, therefore, affected by a privilege
escalation vulnerability due to incorrect permissions of a system
directory at installation time. A local attacker can exploit this, by
creating a specially crafted interprocess communication (IPC) to the
virtual private network (VPN) agent process, to execute commands on
the host with elevated system level privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161207-anyconnect1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f8d0034");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvb68043");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco AnyConnect Secure Mobility Client version 4.3.4019.0
/ 4.4.225.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Cisco AnyConnect Secure Mobility Client";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
path = install['path'];
ver  = install['version'];

fix = '';

if (ver =~ "^4\.4\." && (ver_compare(ver:ver, fix:'4.4.225.0', strict:FALSE) < 0))
  fix = '4.4.225.0';

else if ((ver =~ "^3\.1\.") || ((ver =~ "^4\.[0-3]\.") &&
        (ver_compare(ver:ver, fix:'4.3.4019.0', strict:FALSE) < 0)))
  fix = '4.3.4019.0';

if (!empty(fix))
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(
    port: port,
    severity: SECURITY_HOLE,
    extra: report
  );
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69982);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/05 16:01:13 $");

  script_cve_id("CVE-2013-0940");
  script_bugtraq_id(59620);
  script_osvdb_id(92988);

  script_name(english:"EMC NetWorker nsrpush Process Local Privilege Escalation");
  script_summary(english:"Checks version of EMC NetWorker");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by a local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC NetWorker is earlier than 7.6.5.3 or 8.x earlier
than 8.0.1.4. Such versions are potentially affected by a local
privilege escalation vulnerability in the nsrpush process.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526517/30/270/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to EMC NetWorker 7.6.5.3 / 8.0.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:networker");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("emc_networker_installed.nasl");
  script_require_keys("installed_sw/EMC NetWorker");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname  = "EMC NetWorker";
install  = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
version  = install['version'];
path     = install['path'];

fix = '';
if (ver_compare(ver:version, fix:'7.6.5.3', strict:FALSE) < 0) fix = '7.6.5.3';
else if (version =~ '^8\\.0\\.' && ver_compare(ver:version, fix:'8.0.1.4', strict:FALSE) < 0) fix = '8.0.1.4';

if (fix)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, 'EMC NetWorker', version, path);

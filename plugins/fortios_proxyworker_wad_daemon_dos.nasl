#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85740);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_osvdb_id(125025, 125026);

  script_name(english:"Fortinet FortiOS 5.0.x < 5.0.1 Multiple DoS");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Fortinet FortiOS 5.0.x prior
to 5.0.1. It is, therefore, affected by multiple denial of service
vulnerabilities :

  - A flaw exists related to the handling of SSH traffic. An
    unauthenticated, remote attacker can exploit this to
    crash the proxyworker service. (VulnDB 125025)

  - A flaw exists in the WAD daemon that is triggered during
    the handling of HTTP 0.9 traffic. An unauthenticated,
    remote attacker can exploit this to crash the daemon.
    (VulnDB 125026)");
  # http://kb.fortinet.com/kb/microsites/search.do?cmd=displayKC&docType=kc&externalId=FortiOS-v50-Patch-Release-1-Release-Notespdf
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?fb88f3db");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS 5.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Host/Fortigate/build");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiOS";
model    = get_kb_item_or_exit("Host/Fortigate/model");
version  = get_kb_item_or_exit("Host/Fortigate/version");
build    = get_kb_item_or_exit("Host/Fortigate/build");
vuln     = FALSE;

# Make sure device is FortiGate
if (!preg(string:model, pattern:"fortigate", icase:TRUE)) audit(AUDIT_OS_NOT, app_name);

if (version =~ "^5\.")
{
  fix = "5.0.1";
  fix_build = 147;
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

# If build number is available, this is the safest comparison.
# Otherwise compare version numbers.
if (build !~ "Unknown")
{
  if (int(build) < fix_build) vuln = TRUE;
  report_build = build;
}
else if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1) vuln = TRUE;

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.0.1';
    if (!empty_or_null(report_build))
      report +=
        '\n  Installed build   : ' + report_build +
        '\n  Fixed build       : ' + fix_build;

    report += '\n';
    security_warning(extra:report, port:0);
  }
  else security_warning(port:0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

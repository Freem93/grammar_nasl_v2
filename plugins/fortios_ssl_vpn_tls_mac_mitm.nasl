#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85806);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/08 14:15:23 $");

  script_cve_id("CVE-2015-5965");
  script_bugtraq_id(76065);
  script_osvdb_id(125101);

  script_name(english:"Fortinet FortiOS < 4.3.13 SSL-VPN TLS MAC Spoofing");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a man-in-the-middle spoofing
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 4.3.13. It
is, therefore, affected by a man-in-the-middle spoofing vulnerability
due to a flaw in the SSL-VPN feature. The SSL-VPN feature only
validates the first byte of the TLS MAC in finished messages. A
remote, man-in-the-middle attacker can exploit this, via a crafted
MAC field, to spoof encrypted content, potentially resulting in the
disclosure of sensitive information.");
  # 4.3.13 release notice
  script_set_attribute(attribute:"see_also",value:"https://forum.fortinet.com/tm.aspx?m=96828");
  # 4.3.14 release notice
  script_set_attribute(attribute:"see_also",value:"https://forum.fortinet.com/tm.aspx?m=97337");
  script_set_attribute(attribute:"see_also",value:"https://vivaldi.net/en-US/blogs/entry/the-poodle-has-friends");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS 4.3.14 or later.

Note that version 4.3.13 contained the earliest fix; however, that
version contained an unrelated error and was removed from
distribution.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Host/Fortigate/build", "Settings/ParanoidReport");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^4\.")
{
  fix = "4.3.13";
  fix_build = 664;
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
      '\n  Fixed version     : 4.3.14';
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

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67231);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id("CVE-2013-0169");
  script_bugtraq_id(57778);
  script_osvdb_id(89848);

  script_name(english:"IBM GSKit 7.x < 7.0.4.45 / 8.0.14.x < 8.0.14.27 TLS Side-Channel Timing Information Disclosure");
  script_summary(english:"Checks the version of GSKit.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a library installed that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Global Security Kit (GSKit) installed on the
remote host is 7.0.x prior to 7.0.4.45 or 8.0.14.x prior to 8.0.14.27.
It is, therefore, affected by an information disclosure vulnerability.
The Transport Layer Security (TLS) protocol does not properly
consider timing side-channel attacks, which allows remote attackers
to conduct distinguishing attacks and plain-text recovery attacks via
statistical analysis of timing data for crafted packets. This type of
exploitation is known as the 'Lucky Thirteen' attack.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21638270");
  script_set_attribute(attribute:"solution", value:"Upgrade to GSKit 7.0.4.45 / 8.0.14.27 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:global_security_kit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_gskit_installed.nasl", "ibm_gskit_installed_nix.nbin");
  script_require_keys("installed_sw/IBM GSKit", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "IBM GSKit";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];
fix = NULL;

if (version =~ '^7\\.0\\.' && ver_compare(ver:version, fix:'7.0.4.45') < 0)
  fix = '7.0.4.45';
else if (version =~ '^8\\.0\\.14\\.' && ver_compare(ver:version, fix:'8.0.14.27') < 0)
  fix = '8.0.14.27';
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

# Default to Linux unless the RPM is not set
port = 0;
if (isnull(install['RPM']))
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;
}

if (report_verbosity > 0)
{
  report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix + '\n';

  security_note(port:port, extra:report);
}
else security_note(port);

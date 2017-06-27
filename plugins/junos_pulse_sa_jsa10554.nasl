#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69241);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2012-5460");
  script_bugtraq_id(61399);
  script_osvdb_id(91734);

  script_name(english:"Junos Pulse Secure Access Service (SSL VPN) Multiple XSS (JSA10554)");
  script_summary(english:"Checks OS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of IVE OS running
on the remote host has the following cross-site scripting
vulnerabilities :

  - An unspecified cross-site scripting issue exists related
    to login pages.

  - A cross-site scripting vulnerability exists in the
    WWHSearchWordsText parameter of the help page.

An attacker could exploit either of these issues by tricking a user into
requesting a malicious URL, resulting in arbitrary script code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Jul/147");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10554");
  script_set_attribute(attribute:"solution", value:"Upgrade to Juniper IVE OS version 7.1r13 / 7.2r7 / 7.3r2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/06");  # OSVDB
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/12"); # bugtraq mailing list
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:ive_os");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_pulse_secure_access_service");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Juniper/IVE OS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('Host/Juniper/IVE OS/Version');
match = eregmatch(string:version, pattern:"^([\d.]+)[Rr](\d+)");
if (isnull(match)) exit(1, 'Error parsing version: ' + version);

release = match[1];
build = int(match[2]);

if (release == '7.1' && build < 13)
  fix = '7.1r13';
else if (release == '7.2' && build < 7)
  fix = '7.2r7';
else if (release == '7.3' && build < 2)
  fix = '7.3r2';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'IVE OS', version);

set_kb_item(name:'www/0/XSS', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);

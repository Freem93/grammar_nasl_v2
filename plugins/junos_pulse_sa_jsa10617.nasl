#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73023);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/03 17:40:02 $");

  script_cve_id("CVE-2014-2291");
  script_bugtraq_id(66173);
  script_osvdb_id(104419);

  script_name(english:"Juniper Junos Pulse Secure Access Service IVE OS (SSL VPN) XSS (JSA10617)");
  script_summary(english:"Checks OS version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of Juniper Junos
Pulse Secure Access Service IVE OS running on the remote host is
affected by an unspecified cross-site scripting vulnerability that is
present within the Pulse Collaboration (Secure Meeting) user pages.  An
attacker could exploit this issue by tricking a user into requesting a
malicious URL, resulting in arbitrary script code execution. 

Note that the issue is only present when the Pulse Collaboration feature
is enabled on a user's role."
  );
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10617");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Juniper Junos Pulse Secure Access Service IVE OS version
7.1r18 / 7.3r10 / 7.4r8 / 8.0r1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:ive_os");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_pulse_secure_access_service");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Juniper/IVE OS/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('Host/Juniper/IVE OS/Version');
match = eregmatch(string:version, pattern:"^([\d.]+)([Rr](\d+))?");
if (isnull(match)) exit(1, 'Error parsing version: ' + version);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

release = match[1];
build = 0;
if (!isnull(match[2])) build = int(match[3]);

if (release == '7.1' && build < 18)
  fix = '7.1r18';
else if (release == '7.3' && build < 10)
  fix = '7.3r10';
else if (release == '7.4' && build < 8)
  fix = '7.4r8';
else if (release == '8.0' && build < 1)
  fix = '8.0r1';
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

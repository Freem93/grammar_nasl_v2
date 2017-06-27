#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90098);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/29 19:33:19 $");

  script_cve_id("CVE-2015-7560", "CVE-2016-0771");
  script_osvdb_id(135620, 135621);

  script_name(english:"Samba 3.2.x < 4.1.23 / 4.2.x < 4.2.9 / 4.3.x < 4.3.6 / 4.4.0 < 4.4.0rc4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba running on the remote
host is 3.2.x prior to 4.1.23, 4.2.x prior to 4.2.9, 4.3.x prior to
4.3.6, or 4.4.0 prior to 4.4.0rc4. It is, therefore, affected by the
following vulnerabilities :

  - A security bypass vulnerability exists in the SMB1
    implementation that is triggered when a symlink created
    to a file or directory using SMB1 UNIX extensions is
    accessed using non-UNIX SMB1 calls. An authenticated,
    remote attacker can exploit this to overwrite file and
    directory ACLs. (CVE-2015-7560)

  - An out-of-bounds read error exists in the internal DNS
    server due to improper handling of TXT records when an
    AD DC is configured. An authenticated, remote attacker
    can exploit this, via a crafted DNS TXT record, to cause
    a crash or disclose memory contents. (CVE-2016-0771)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2015-7560.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2016-0771.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.1.23.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.2.9.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.3.6.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.1.23 / 4.2.9 / 4.3.6 / 4.4.0rc4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

lanman = get_kb_item_or_exit("SMB/NativeLanManager");

if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);

version = lanman - 'Samba ';

if (version =~ "^4(\.[1-4])?$" || version =~ "^3$")
  audit(AUDIT_VER_NOT_GRANULAR, "Samba", port, version);

fix = NULL;

regexes = make_array(-1, "rc(\d+)");

# Affected :
# 3.2.x < 4.1.23
# 4.2.x < 4.2.9
# 4.3.x < 4.3.6
# 4.4.0 < 4.4.0rc4
if (
  (
    version =~ "^3\." &&
    version !~ "^3\.[01]\."
  ) ||
  version =~ "^4\.[01]\."
)
  fix = '4.1.23';
if (version =~ "^4\.2\.")
  fix = '4.2.9';
if (version =~ "^4\.3\.")
  fix = '4.3.6';
if (version =~ "^4\.4\.")
  fix = '4.4.0rc4';

if (ver_compare(ver:version, fix:fix, regexes:regexes) < 0)
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fix +
           '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra: report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81485);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/06/16 17:06:58 $");

  script_cve_id("CVE-2015-0240");
  script_bugtraq_id(72711);
  script_osvdb_id(118637);

  script_name(english:"Samba 3.5.x < 3.5.22 / 3.6.x < 3.6.25 / 4.0.x < 4.0.25 / 4.1.x < 4.1.17 TALLOC_FREE() RCE");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba running on the remote
host is 3.5.x prior to 3.5.22, 3.6.x prior to 3.6.25, 4.0.x prior to
4.0.25, or 4.1.x prior to 4.1.17. It is, therefore, affected by a
remote code execution vulnerability in the TALLOC_FREE() function of
'rpc_server/netlogon/srv_netlog_nt.c'. A remote attacker, using a
specially crafted sequence of packets followed by a subsequent
anonymous netlogon packet, can execute arbitrary code as the root
user.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2015-0240.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.6.25.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.0.25.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.1.17.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba 3.6.25 / 4.0.25 / 4.1.17 or later. Alternatively,
install the patch or apply the workaround referenced in the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

if (lanman =~ '^Samba 3(\\.[56])?$' || lanman =~ '^Samba 4(\\.[0-2])?$')
  audit(AUDIT_VER_NOT_GRANULAR, "Samba", port, version);

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = NULL;

if (
  (ver[0] == 3 && ver[1] == 5 && ver[2] <= 22) ||
  (ver[0] == 3 && ver[1] == 6 && ver[2] < 25)
)
  fix = '3.6.25';
if (ver[0] == 4 && ver[1] == 0 && ver[2] < 25) fix = '4.0.25';
if (ver[0] == 4 && ver[1] == 1 && ver[2] < 17) fix = '4.1.17';

# Note that 4.2.x < 4.2.0rc5 is vuln,
# but we don't make much noise about it.
if (version =~ "^4\.2\.0rc[0-4]$") fix = '4.2.0rc5';

if (fix)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);

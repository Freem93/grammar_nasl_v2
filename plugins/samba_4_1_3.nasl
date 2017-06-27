#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71377);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/16 17:06:58 $");

  script_cve_id("CVE-2012-6150", "CVE-2013-4408");
  script_bugtraq_id(64101, 64191);
  script_osvdb_id(100749, 102653);

  script_name(english:"Samba 3.x < 3.6.22 / 4.0.x < 4.0.13 / 4.1.x < 4.1.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba running on the remote
host is 3.3.x equal or later than 3.3.10, 3.4.x, 3.5.x, 3.6.x prior to
3.6.22, 4.0.x prior to 4.0.13 or 4.1.x prior to 4.1.3.  It is,
therefore, potentially affected by multiple vulnerabilities :

  - A security bypass vulnerability exists in the
    'winbind_name_list_to_sid_string_list()' function of the
    'nsswitch/pam_winbind.c' source file. Exploitation could
    allow a malicious, authenticated user access to the
    'pam_winbind' configuration file. (CVE-2012-6150)

  - A buffer overflow exists in the
    'dcerpc_read_ncacn_packet_done' function of the
    'librpc/rpc/dcerpc_util.c' source file that could allow
    remote AD domain controllers to execute arbitrary code
    on the remote host via DCE-RPC packet with an invalid
    fragment length. (CVE-2013-4408)

Note that Nessus has relied only on the self-reported version number and
has not actually tried to exploit this issue or determine if the
associated patch has been applied.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2012-6150.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2013-4408.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.6.22 / 4.0.13 / 4.1.3 or later or refer to the
vendor for a patch or workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

lanman = get_kb_item_or_exit("SMB/NativeLanManager");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  lanman =~ '^Samba 3(\\.[3-6])?$' ||
  lanman =~ '^Samba 4(\\.[0-1])?$'
) exit(1, "The version, "+lanman+", of the SMB service listening on port "+port+" is not granular enough to make a determination.");

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affected :
# 3.3.x >= 3.3.10
# 3.4.x
# 3.5.x
# 3.6.x < 3.6.22
# 4.0.x < 4.0.13
# 4.1.x < 4.1.3
if (
  (ver[0] == 3 && ver[1] == 3 && ver[1] >= 10) ||
  (ver[0] == 3 && ver[1] == 4) ||
  (ver[0] == 3 && ver[1] == 5) ||
  (ver[0] == 3 && ver[1] == 6 && ver[2] < 22) ||
  (ver[0] == 4 && ver[1] == 0 && ver[2] < 13) ||
  (ver[0] == 4 && ver[1] == 1 && ver[2] < 3)
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : 3.6.22 / 4.0.13 / 4.1.3\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);

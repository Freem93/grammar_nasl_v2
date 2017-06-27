#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73080);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/16 17:06:58 $");

  script_cve_id("CVE-2013-4496", "CVE-2013-6442");
  script_bugtraq_id(66232, 66336);
  script_osvdb_id(104373, 104374);

  script_name(english:"Samba 3.4.x < 3.6.23 / 4.0.x < 4.0.16 / 4.1.x < 4.1.6 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:"The remote Samba server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba running on the remote
host is 3.4.x or later but prior to 3.6.23 or 4.0.x or later but prior
to 4.0.16 or 4.1.6.  It is, therefore, potentially affected by multiple
vulnerabilities :

  - A flaw exists in the Security Account Manager Remote
    protocol implementation where it fails to validate the
    user lockout state, affecting Samba versions 3.4.x and
    later. This could allow a remote attacker to attempt a
    brute-force attack to determine a user's password
    without being locked out. (CVE-2013-4496)

  - A flaw exists in the 'owner_set' function of the
    smbcacls command when changing the owner or group owner
    of the object using '-C' / '--chown' or '-G' / '--chgrp'
    flags, causing the existing ACL to be removed. This
    affects Samba versions 4.0.x and later and could allow
    an attacker unrestricted access to the modified object.
    (CVE-2013-6442)

Note that Nessus has relied only on the self-reported version number and
has not actually tried to exploit these issues or determine if the
associated patches have been applied.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2013-4496.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2013-6442.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.6.23.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.0.16.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.1.6.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.6.23 / 4.0.16 / 4.1.6 or later or refer to the
vendor for patches or workarounds.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

# Granularity Check
if (
  lanman =~ "^Samba 3(\.6)?$" ||
  lanman =~ "^Samba 4(\.[0-1])?$"
) audit(AUDIT_VER_NOT_GRANULAR, "Samba", port, lanman);

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affected :
# 3.4.x < 3.6.23
# 4.0.x < 4.0.16
# 4.1.x < 4.1.6
if (
  (ver[0] == 3 && ver[1] == 4) ||
  (ver[0] == 3 && ver[1] == 5) ||
  (ver[0] == 3 && ver[1] == 6 && ver[2] < 23) ||
  (ver[0] == 4 && ver[1] == 0 && ver[2] < 16) ||
  (ver[0] == 4 && ver[1] == 1 && ver[2] < 6)
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : 3.6.23 / 4.0.16 / 4.1.6\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);

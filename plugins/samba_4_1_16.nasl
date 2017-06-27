#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80916);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/06/16 17:06:58 $");

  script_cve_id("CVE-2014-8143");
  script_bugtraq_id(72278);
  script_osvdb_id(117132);

  script_name(english:"Samba 4.x < 4.0.24 / 4.1.16 UF_SERVER_TRUST_ACCOUNT AD DC Privilege Escalation");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba on the remote host is
4.x prior to 4.0.24 / 4.1.16. It is, therefore, affected by a flaw in
the Active Directory Domain Controller (AD DC) component due to a
failure to implement a required check on the 'UF_SERVER_TRUST_ACCOUNT'
bit of the 'userAccountControl' attributes. This vulnerability could
allow a remote, authenticated attacker to elevate privileges.

Note that this issue only affects Samba installations acting as Active
Directory Domain Controllers that allow delegation for the creation of
user or computer accounts.

Also note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2014-8143.html");
  # https://www.samba.org/samba/ftp/patches/security/samba-4.0.23-CVE-2014-8143.patch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f3a3084");
  # https://www.samba.org/samba/ftp/patches/security/samba-4.1.15-CVE-2014-8143.patch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c7d41bf");
  script_set_attribute(attribute:"solution", value:
"Install the patch referenced in the project's advisory or upgrade to
4.0.24 / 4.1.16 or later.

Alternatively, as a workaround, do not delegate permission to create
users or computers to entities other than Domain Administrators.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/22");

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

port = get_kb_item("SMB/transport");
if (!port) port = 445;

lanman = get_kb_item_or_exit("SMB/NativeLanManager");

if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  lanman =~ '^Samba 4(\\.0)?$' ||
  lanman =~ '^Samba 4(\\.1)?$' ||
  lanman =~ '^Samba 4(\\.2)?$'
)
  audit(AUDIT_VER_NOT_GRANULAR, "Samba", port, version);
if (lanman !~ "^Samba 4\.[012]($|[^0-9])")
  audit(AUDIT_NOT_LISTEN, "Samba 4.0.x / 4.1.x / 4.2.x", port);

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = NULL;

if (ver[0] == 4 && ver[1] == 0 && ver[2] < 24) fix = '4.0.24';
if (ver[0] == 4 && ver[1] == 1 && ver[2] < 16) fix = '4.1.16';

# Note too that 4.2.x < 4.2.0rc4 is vuln,
# but we don't make much noise about it.
if (version =~ "^4\.2\.0rc[0-3]$") fix = '4.2.0rc4';

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

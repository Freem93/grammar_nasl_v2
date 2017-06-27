#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76973);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/06/16 17:06:58 $");

  script_cve_id("CVE-2014-3560");
  script_bugtraq_id(69021);

  script_name(english:"Samba 4.x < 4.0.21 / 4.1.11 nmbd Remote Code Execution");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba on the remote host is
4.x prior to 4.0.21 / 4.1.11. It is, therefore, affected by a flaw in
the NetBIOS name services daemon (nmbd). This flaw may allow an
attacker to execute arbitrary code as the superuser.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2014-3560.html");
  # http://ftp.samba.org/pub/samba/patches/security/samba-4.1.10-CVE-2014-3560.patch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54321287");
  script_set_attribute(attribute:"solution", value:
"Install the patch referenced in the project's advisory or upgrade to
4.0.21 / 4.1.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/01");

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

port = get_kb_item("SMB/transport");
if (!port) port = 445;

lanman = get_kb_item_or_exit("SMB/NativeLanManager");

if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (lanman =~ '^Samba 4(\\.0)?$' || lanman =~ '^Samba 4(\\.1)?$')
  audit(AUDIT_VER_NOT_GRANULAR, "Samba", port, version);

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = NULL;

if (ver[0] == 4 && ver[1] == 0 && ver[2] < 21) fix = '4.0.21';
if (ver[0] == 4 && ver[1] == 1 && ver[2] < 11) fix = '4.1.11';

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

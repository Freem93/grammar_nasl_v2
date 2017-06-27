#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(65631);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/16 17:06:58 $");

  script_cve_id("CVE-2013-1863");
  script_bugtraq_id(58596);
  script_osvdb_id(91503);

  script_name(english:"Samba 4.x < 4.0.4 AD DC File Permissions");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by a permissions vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba running on the remote
host is 4.x prior to 4.0.4 and is, therefore, potentially affected by a
file permissions vulnerability. 

Files on Active Directory Domain Controllers(AD DC) may be created with
world-writeable permissions when additional CIFS file shares are created
on the AD DC. 

Note that this issue does not affect the AD DC by default and thus, does
not affect files in the 'sysvol' and 'netlogon' shares.  Further,
installs configured as standalone server, domain member, file server,
classic domain controller and installs built with '--without-ad-dc' are
not affected.  However, it does affect files on shares with simple Unix
permissions. 

Further note that Nessus has relied only on the self-reported version
number and has not actually tried to exploit this issue, or determine if
the associated patch has been applied.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2013-1863.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.0.4.html");
  # http://ftp.samba.org/pub/samba/patches/security/samba-4.0.3-CVE-2013-1863.patch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1e441d9");
  script_set_attribute(attribute:"solution", value:
"Either install the patch referenced in the project's advisory, or
upgrade to 4.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/20");

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


port = get_kb_item("SMB/transport");
lanman = get_kb_item_or_exit("SMB/NativeLanManager");

if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (lanman =~ '^Samba 4(\\.0)?$') exit(1, "The version, "+lanman+", of the SMB service listening on port "+port+" is not granular enough to make a determination.");

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 4 && ver[1] == 0 && ver[2] < 4)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version  : ' + version +
             '\n  Fixed version      : 4.0.4\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);

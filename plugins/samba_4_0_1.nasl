#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(63561);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/16 17:06:58 $");

  script_cve_id("CVE-2013-0172");
  script_bugtraq_id(57329);
  script_osvdb_id(89180);

  script_name(english:"Samba 4.x < 4.0.1 AD DC LDAP Directory Objects Security Bypass");
  script_summary(english:"Checks version of Samba");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba 4.x running on the remote
host is earlier than 4.0.1, and is, therefore, potentially affected by a
security bypass vulnerability. 

When acting as an Active Directory (AD) Domain Controller (DC), the
application can improperly grant write access to an LDAP directory
object or its attributes improperly.  This error can be triggered when a
user or group is granted any access to an LDAP directory object based on
objectClass or is granted write access to any attribute on the object. 

Note that, by default, the application does not make 'authenticated
users' a part of the 'pre-windows 2000 compatible access' group, which
is the group that typically receives the problematic per-objectClass
permission. 

Further note that Nessus has not actually tried to exploit this issue or
otherwise determine if the patch or workaround has been applied.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2013-0172.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.0.1.html");
  # http://www.samba.org/samba/ftp/patches/security/samba-4.0.0-CVE-2013-0172.patch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24a2ba59");
  script_set_attribute(attribute:"solution", value:
"Either install the patch referenced in the project's advisory or
upgrade to 4.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/16");

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


if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("SMB/transport");
lanman = get_kb_item_or_exit("SMB/NativeLanManager");

if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);
if (lanman =~ '^Samba 4(\\.0)?$') exit(1, "The version, "+lanman+", of the SMB service listening on port "+port+" is not granular enough to make a determination.");

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 4 && ver[1] == 0 && ver[2] == 0)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version  : ' + version + 
             '\n  Fixed version      : 4.0.1\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);

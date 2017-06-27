#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17719);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/16 17:06:58 $");

  script_cve_id("CVE-2007-4138");
  script_bugtraq_id(25636);
  script_osvdb_id(39178);

  script_name(english:"Samba idmap_ad.so Winbind nss_info Extension Local Privilege Escalation");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by a local privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Samba server installed on
the remote host is affected by a local privilege escalation
vulnerability. Specifically, the Winbind nss_info extension, when the
'winbind nss info' option is set to 'rfc2307' or 'sfu', grants local
users the privileges of gid 0 if the 'RFC2307' or 'Services for UNIX'
primary group attribute is not defined.");

  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2007-4138.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Samba version 3.0.26 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_kb_item_or_exit("SMB/transport");

lanman = get_kb_item_or_exit("SMB/NativeLanManager");
if ("Samba " >!< lanman) exit(0, "The SMB service listening on port "+port+" is not running Samba.");

version = lanman - 'Samba ';

if (ereg(pattern:"^3\.0\.25($|[^0-9a-z]|pre|rc|[a-c])[^0-9]*$", string:version, icase:TRUE))
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version  : ' + version +
             '\n  Fixed version      : 3.0.26\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The Samba "+version+" install listening on port "+port+" is not affected.");

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39502);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2009-1886", "CVE-2009-1888", "CVE-2006-3403");
  script_bugtraq_id(35472);
  script_osvdb_id(27130, 55411, 55412);
  script_xref(name:"Secunia", value:"35539");

  script_name(english:"Samba < 3.0.35 / 3.2.13 / 3.3.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the remote Samba version");

  script_set_attribute( attribute:"synopsis", value:
"The remote Samba server may be affected by a security bypass
vulnerability."  );
  script_set_attribute( attribute:"description", value:
"According to its version number, the version of Samba running on the
remote host has a security bypass vulnerability.  Access restrictions
can be bypassed due to a read of uninitialized data in smbd.  This
could allow a user to modify an access control list (ACL), even when
they should be denied permission.

Note the 'dos filemode' parameter must be set to 'yes' in smb.conf
in order for an attack to be successful (the default setting is 'no').

Also note versions 3.2.0 - 3.2.12 of smbclient are affected by a
format string vulnerability, though Nessus has not checked for this."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://us1.samba.org/samba/security/CVE-2009-1888.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://us1.samba.org/samba/security/CVE-2009-1886.html"
  );
  script_set_attribute( attribute:"solution", value:
"Upgrade to Samba version 3.3.6 / 3.2.13 / 3.0.35 or later, or apply
the appropriate patch referenced in the vendor's advisory."  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(134, 264);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/24");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_cvs_date("$Date: 2016/12/14 20:22:11 $");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/samba", "SMB/NativeLanManager");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (report_paranoia < 2)
  exit(1, "Report paranoia is low, and this plugin's prone to false positives");

lanman = get_kb_item("SMB/NativeLanManager");
if (isnull(lanman))
  exit(1, "A SMB banner was not found.");

match = eregmatch(string:lanman, pattern:'^Samba ([0-9.]+)$', icase:TRUE);
if (isnull(match))
  exit(1, "The banner does not appear to be Samba.");

version = match[1];
ver_fields = split(version, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

# Affected versions:
# 3.3.0 - 3.3.5
# 3.2.0 - 3.2.12
# 3.0.0 - 3.0.34
if (
  major == 3 &&
    ((minor == 3 && rev <= 5) ||
     (minor == 2 && rev <= 12) ||
     (minor == 0 && rev <= 34))
)
{
  port = get_kb_item("SMB/transport");

  if (minor == 3) fix = '3.3.6';
  else if (minor == 2) fix = '3.2.13';
  else if (minor == 0) fix = '3.0.35';

  if (report_verbosity)
  {
    report = string(
      "\n",
      "Installed version : ", version, "\n",
      "Fixed version     : ", fix, "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);

  exit(0);
}
else exit(1, "Samba version " + version + " is not vulnerable.");


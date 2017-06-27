#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45046);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id("CVE-2010-0728");
  script_bugtraq_id(38606);
  script_osvdb_id(62803);

  script_name(english:"Samba 'CAP_DAC_OVERRIDE' File Permission Security Bypass (version check)");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:"The remote file server is vulnerable to a security bypass attack.");
  script_set_attribute(attribute:"description", value:
"The remote Samba server is potentially affected by a security bypass
vulnerability because of a flaw that causes all smbd processes, when
libcap support is enabled, to inherit 'CAP_DAC_OVERRIDE' capabilities,
which in turn causes all file system access to be allowed even when
permissions should have been denied.

A remote, authenticated attacker may be able to exploit this flaw to
gain access to sensitive information on Samba shares that are
accessible to their user id.");
  script_set_attribute(attribute:"see_also", value:"http://us1.samba.org/samba/security/CVE-2010-0728.html");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.samba.org/show_bug.cgi?id=7222");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Samba 3.3.12, 3.4.7, 3.5.1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/samba", "SMB/NativeLanManager", "SMB/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

lanman = get_kb_item("SMB/NativeLanManager");
if (isnull(lanman)) exit(1, "The 'SMB/NativeLanManager' KB item is missing.");
if ("samba " >!< tolower(lanman)) exit(0, "The host is not using Samba.");

# nb: the vulnerability was introduced in 3.5.0 / 3.4.6 / 3.3.11 - only
#     those versions are affected.
if (
  ereg(pattern:"Samba 3\.(3\.11|4\.6|)($|[^[0-9])", string:lanman, icase:TRUE) ||
  ereg(pattern:"Samba 3\.5([^\.0-9]|\.0|$)", string:lanman, icase:TRUE)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'The remote Samba server appears to be :\n' +
      '\n' +
      '  ' + lanman + '\n';
    security_hole(port:get_kb_item("SMB/transport"),extra:report);
  }
  else security_hole(port:get_kb_item("SMB/transport"));
  exit(0);
}
exit(0, "The host is not affected because " + lanman + " is installed.");

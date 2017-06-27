#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38972);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2009-1636");
  script_bugtraq_id(35064, 35065);
  script_xref(name:"OSVDB", value:"54644");
  script_xref(name:"OSVDB", value:"54645");

  script_name(english:"Novell GroupWise Internet Agent < 7.03 HP3 / 8.0 HP2 Multiple Buffer Overflows");
  script_summary(english:"Does a local check for the version of gwia.exe");

  script_set_attribute(attribute:"synopsis", value:
"The SMTP server running on the remote Windows host has multiple
buffer overflow vulnerabilities."  );
  script_set_attribute( attribute:"description", value:
"A vulnerable version of GroupWise Internet Agent is running on the
remote host.  The software contains unspecified buffer overflow
vulnerabilities that are triggered when processing email addresses
and other specially crafted SMTP requests.

This could allow a remote attacker to crash the service or execute
arbitrary code as SYSTEM."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.novell.com/support/viewContent.do?externalId=7003272&sliceId=1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.novell.com/support/viewContent.do?externalId=7003273&sliceId=1"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Novell GroupWise version 7.03 HP3 / 8.0 HP2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/01");
 script_cvs_date("$Date: 2016/05/16 14:02:51 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("groupwise_ia_detect.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/GWIA/Version");
 
  exit(0);
}


include("global_settings.inc");


version = get_kb_item("SMB/GWIA/Version");
if (isnull(version)) exit(0);

ver_fields = split(version, sep:'.', keep:FALSE);
major = ver_fields[0];
minor = ver_fields[1];
build = ver_fields[2];
revision = ver_fields[3];

# First, see if the version is vulnerable (< 8.0.0.7328, < 7.0.3.1401)
if (
  (major == 8 && minor == 0 && build == 0 && revision < 7328) ||
  (major == 7 && minor == 0 && (build < 3 || (build == 3 && revision < 1401)))
)
  vulnerable = TRUE;
else
  vulnerable = FALSE;

if (!vulnerable) exit(0);

# Make sure the service is running, unless we're paranoid
if (report_paranoia < 2)
{
  services = get_kb_item("SMB/svcs");

  if (isnull(services) || "GWIA" >!< services) exit(0);
}

if (report_verbosity > 0)
{
  if (major == 7) patched_ver = "7.0.3.1401";
  else if (major == 8) patched_ver = "8.0.0.7328";

  report = string(
    "\n",
    "The remote version of GroupWise Internet Agent (gwia.exe) has not been\n",
    "patched :\n",
    "\n",
    "  Remote version : ", version, "\n",
    "  Should be      : ", patched_ver, "\n"
  );
  security_hole(port:get_kb_item("SMB/transport"), extra:report);
}
else security_hole(get_kb_item("SMB/transport"));


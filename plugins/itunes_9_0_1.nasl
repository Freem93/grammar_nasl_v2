#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(41060);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2009-2817");
  script_bugtraq_id(36478);
  script_osvdb_id(58271);

  script_name(english:"Apple iTunes < 9.0.1 PLS File Buffer Overflow (credentialed check)");
  script_summary(english:"Checks version of iTunes on Windows");

  script_set_attribute( attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
buffer overflow vulnerability."  );
  script_set_attribute( attribute:"description", value:
"The remote version of Apple iTunes is older than 9.0.1. Such versions
are affected by a buffer overflow involving the handling of PLS files.
If an attacker can trick a user on the affected host into opening a
malicious PLS file, he can leverage this issue to crash the affected
application or to execute arbitrary code on the affected system
subject to the user's privileges."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3884"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/Sep/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/17952"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Apple iTunes 9.0.1 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(119);
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/09/22"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/09/23"
  );
 script_cvs_date("$Date: 2015/08/03 13:57:40 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
  script_dependencies("itunes_detect.nasl");
  script_require_keys("SMB/iTunes/Version");

  exit(0);
}


include ("global_settings.inc");


version = get_kb_item("SMB/iTunes/Version");
if (isnull(version)) exit(1, "The 'SMB/iTunes/Version' KB item is missing.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 9 ||
  (
    ver[0] == 9 && ver[1] == 0 && 
    (
      ver[2] < 1 ||
      (ver[2] == 1 && ver[3] < 8)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "iTunes ", version, " is installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The host is not affected since iTunes "+version+" is installed.");

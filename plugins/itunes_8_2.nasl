#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38985);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2009-0950");
  script_bugtraq_id(35157);
  script_osvdb_id(54833);

  script_name(english:"Apple iTunes < 8.2 itms: URI Handling Overflow (credentialed check)");
  script_summary(english:"Checks version of iTunes on Windows");

  script_set_attribute( attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
buffer overflow vulnerability."  );
  script_set_attribute( attribute:"description", value:
"The remote version of Apple iTunes is older than 8.2. Such versions
are affected by a stack-based buffer overflow that can be triggered
when parsing 'itms:' URLs. If an attacker can trick a user on the
affected host into clicking on a malicious link, he can leverage this
issue to crash the affected application or to execute arbitrary code
on the affected system subject to the user's privileges."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3592"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/Jun/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Apple iTunes 8.2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple OS X iTunes 8.1.1 ITMS Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/02");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_dependencies("itunes_detect.nasl");
  script_require_keys("SMB/iTunes/Version");

  exit(0);
}


include ("global_settings.inc");


version = get_kb_item("SMB/iTunes/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if(
  ver[0] < 8 ||
  (
    ver[0] == 8 &&
    (
      ver[1] < 2 ||
      (
        ver[1] == 2 && ver[2] == 0 && ver[3] < 23
      )
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

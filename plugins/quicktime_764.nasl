#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40929);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2009-2202", "CVE-2009-2203", "CVE-2009-2798", "CVE-2009-2799");
  script_bugtraq_id(36328);
  script_osvdb_id(57861, 57862, 57863, 57864);

  script_name(english:"QuickTime < 7.6.4 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks version of QuickTime on Windows");

  script_set_attribute( attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities."  );
  script_set_attribute( attribute:"description", value:
"The version of QuickTime installed on the remote Windows host is older
than 7.6.4.  Such versions contain several vulnerabilities :

  - A memory corruption issue in QuickTime's handling of
    H.264 movie files may lead to an application crash
    or arbitrary code execution. (CVE-2009-2202)

  - A buffer overflow in QuickTime's handling of MPEG-4
    video files may lead to an application crash or
    arbitrary code execution. (CVE-2009-2203)

  - A heap-based buffer overflow in QuickTime's handling of
    FlashPix files may lead to an application crash or
    arbitrary code execution. (CVE-2009-2798)

  - A heap-based buffer overflow in QuickTime's handling of
    H.264 movie files may lead to an application crash or
    arbitrary code execution. (CVE-2009-2799)");
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2009/Sep/msg00002.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to QuickTime 7.6.4 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/09"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/10"
  );
 script_cvs_date("$Date: 2014/05/12 22:56:25 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");
  exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/QuickTime/Version_UI");
version = get_kb_item("SMB/QuickTime/Version");
if (isnull(version)) exit(1, "The 'SMB/QuickTime/Version' KB item is missing.");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 7 || 
  (
    ver[0] == 7 && 
    (
      ver[1] < 64 ||
      (
        ver[1] == 64 && 
        (
          ver[2] < 17 ||
          (ver[2] == 17 && ver[3] < 73)
        )
      )
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "QuickTime ", version_report, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The host is not affected since QuickTime "+version_report+" is installed.");

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40928);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2009-2202", "CVE-2009-2203", "CVE-2009-2798", "CVE-2009-2799");
  script_bugtraq_id(36328);
  script_osvdb_id(57861, 57862, 57863, 57864);

  script_name(english:"QuickTime < 7.6.4 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of QuickTime on Mac OS X");

  script_set_attribute( attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by
multiple vulnerabilities."  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of QuickTime installed on the remote Mac OS X host is
older than 7.6.4.  Such versions contain several vulnerabilities :

  - A memory corruption issue in QuickTime's handling of
    H.264 movie files may lead to an application crash
    or arbitrary code execution. (CVE-2009-2202)

  - A buffer overflow in QuickTime's handling of MPEG-4
    video files may lead to an application crash or
    arbitrary code execution. (CVE-2009-2203)

  - A heap buffer overflow in QuickTime's handling of
    FlashPix files may lead to an application crash or 
    arbitrary code execution. (CVE-2009-2798)

  - A heap buffer overflow in QuickTime's handling of H.264
    movie files may lead to an application crash or
    arbitrary code execution. (CVE-2009-2799)"  );
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
 script_cvs_date("$Date: 2012/02/06 18:28:58 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2009-2012 Tenable Network Security, Inc.");
  script_dependencies("macosx_Quicktime652.nasl");
  script_require_keys("MacOSX/QuickTime/Version");
  exit(0);
}

#

include("global_settings.inc");


version = get_kb_item("MacOSX/QuickTime/Version");
if (isnull(version)) exit(1, "The 'MacOSX/QuickTime/Version' KB item is missing.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

#
# Snow Leopard ships with QuickTime 7.6.3 which is not affected
# by this issue
#
if (
  ver[0] < 7 || 
  (
    ver[0] == 7 && 
    (
      ver[1] < 6 ||
      (ver[1] == 6 && ver[2] < 3)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "QuickTime ", version, " is currently installed on the remote host.\n"
    );
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host is not affected since QuickTime "+version+" is installed.");

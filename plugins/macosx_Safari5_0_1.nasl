#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47887);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id(
    "CVE-2010-1778",
    "CVE-2010-1780",
    "CVE-2010-1782",
    "CVE-2010-1783",
    "CVE-2010-1784",
    "CVE-2010-1785",
    "CVE-2010-1786",
    "CVE-2010-1787",
    "CVE-2010-1788",
    "CVE-2010-1789",
    "CVE-2010-1790",
    "CVE-2010-1791",
    "CVE-2010-1792",
    "CVE-2010-1793",
    "CVE-2010-1796"
  );
  script_bugtraq_id(
    41884,
    42034,
    42035, 
    42036,
    42037,
    42038,
    42039,
    42041,
    42042,
    42043,
    42044,
    42045,
    42046,
    42048,
    42049
  );
  script_osvdb_id(
    66513,
    66844,
    66845,
    66846,
    66847,
    66848,
    66849,
    66850,
    66851,
    66852,
    66853,
    66854,
    66855,
    66856,
    66857
  );

  script_name(english:"Mac OS X : Apple Safari < 5.0.1 / 4.1.1");
  script_summary(english:"Check the Safari SourceVersion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by several
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of Apple Safari installed on the remote Mac OS X host is
earlier than 5.0.1 / 4.1.1.  As such, it is potentially affected by
numerous issues in the following components :

  - Safari

  - WebKit"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4276"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2010/Jul/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Apple Safari 5.0.1 / 4.1.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
 
  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

uname = get_kb_item_or_exit("Host/uname");
if (!egrep(pattern:"Darwin.* (8\.|9\.[0-8]\.|10\.)", string:uname)) audit(AUDIT_OS_NOT, "Mac OS X 10.4 / 10.5 / 10.6");


get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

if (egrep(pattern:"Darwin.* 8\.", string:uname)) fixed_version = "4.1.1";
else fixed_version = "5.0.1";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Safari", version);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51773);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/02 14:37:07 $");

  script_cve_id(
    "CVE-2010-2935",
    "CVE-2010-2936",
    "CVE-2010-3450",
    "CVE-2010-3451",
    "CVE-2010-3452",
    "CVE-2010-3453",
    "CVE-2010-3454",
    "CVE-2010-3702",
    "CVE-2010-3704",
    "CVE-2010-4008",
    "CVE-2010-4253",
    "CVE-2010-4494",
    "CVE-2010-4643"
  );
  script_bugtraq_id(42202, 44779, 45617, 46031);
  script_osvdb_id(
    67041,
    69062,
    69064,
    69205,
    70711,
    70712,
    70713,
    70714,
    70715,
    70717,
    70718
  );
  script_xref(name:"Secunia", value:"40775");

  script_name(english:"Oracle OpenOffice.org < 3.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of OpenOffice.org.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a program affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Oracle OpenOffice.org installed on the remote host is 
prior to 3.3. It is, therefore, affected by several issues :

  - Issues exist relating to PowerPoint document processing
    that may lead to arbitrary code execution.
    (CVE-2010-2935, CVE-2010-2936)

  - A directory traversal vulnerability exists in zip / jar
    package extraction. (CVE-2010-3450)

  - Issues exist relating to RTF document processing that
    may lead to arbitrary code execution. (CVE-2010-3451,
    CVE-2010-3452)

  - Issues exist relating to Word document processing that
    may lead to arbitrary code execution. (CVE-2010-3453,
    CVE-2010-3454)

  - Issues exist in the third-party XPDF library relating
    to PDF document processing that may allow arbitrary code
    execution. (CVE-2010-3702, CVE-2010-3704)

  - OpenOffice.org includes a version of LIBXML2 that is
    affected by multiple vulnerabilities. (CVE-2010-4008,
    CVE-2010-4494)

  - An issue exists with PNG file processing that may allow
    arbitrary code execution. (CVE-2010-4253)

  - An issue exists with TGA file processing that may allow
    arbitrary code execution. (CVE-2010-4643)");

  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2011/Jan/487");
  script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2010-2935_CVE-2010-2936.html");
  script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2010-3450.html");
  script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2010-3451_CVE-2010-3452.html");
  script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2010-3453_CVE-2010-3454.html");
  script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2010-3702_CVE-2010-3704.html");
  script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2010-4008_CVE-2010-4494.html");
  script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2010-4253.html");
  script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2010-4643.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Oracle OpenOffice.org version 3.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date",value:"2011/01/26");
  script_set_attribute(attribute:"patch_publication_date",value:"2011/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:openoffice.org");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("openoffice_installed.nasl");
  script_require_keys("SMB/OpenOffice/Build");

  exit(0);
}


build = get_kb_item("SMB/OpenOffice/Build");
if (build)
{
  matches = eregmatch(string:build, pattern:"([0-9]+[a-z][0-9]+)\(Build:([0-9]+)\)");
  if (!isnull(matches))
  {
    buildid = int(matches[2]);
    if (buildid < 9567) 
      security_hole(get_kb_item("SMB/transport"));
    else
     exit(0,"Build " + buildid + " is not affected.");
  }
  else exit(1, "Failed to extract the build number from '"+build+"'.");
}
else exit(1, "The 'SMB/OpenOffice/Build' KB item is missing.");

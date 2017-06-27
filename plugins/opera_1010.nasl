#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42892);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2009-0689", "CVE-2009-4071", "CVE-2009-4072");
  script_bugtraq_id(37078, 37089);
  script_osvdb_id(60527, 60528);
  script_xref(name:"Secunia", value:"37469");

  script_name(english:"Opera < 10.10 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by multiple
issues."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Opera installed on the remote host is earlier than
10.10.  Such versions are potentially affected by multiple issues :

  - Error messages can leak onto unrelated sites which could
    lead to cross-site scripting attacks. (941)

  - Passing very long strings through the string to number
    conversion using JavaScript in Opera may result in heap 
    buffer overflows. (942)
    
  - There is an as-yet unspecified moderately severe issue
    reported by Chris Evans of the Google Security Team."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/941/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/942/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/docs/changelogs/windows/1010/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/507980/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Opera 10.10 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 119);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/11/20"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/11/23"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/25"
  );
 script_cvs_date("$Date: 2016/12/07 20:46:55 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("global_settings.inc");

version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(1, "The 'SMB/Opera/Version' KB item is missing.");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 10 ||
  (ver[0] == 10 && ver[1] < 10)
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Opera ", version_report, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(port:get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Opera "+version_report+" is installed.");

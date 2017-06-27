#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44595);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/07/28 20:23:55 $");

  script_cve_id("CVE-2010-0186", "CVE-2010-0187");
  script_bugtraq_id(38198, 38200);
  script_osvdb_id(62300, 62370);
  script_xref(name:"Secunia", value:"38547");

  script_name(english:"Adobe AIR < 1.5.3.9130 Multiple Vulnerabilities (APSB10-06)");
  script_summary(english:"Checks version of Adobe AIR");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a version of Adobe AIR that is 
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe AIR that is
earlier than 1.5.3.9130 Such versions are potentially affected by
multiple vulnerabilities :

  - An issue that could subvert the domain sandbox and make
    unauthorized cross-domain requests. (CVE-2010-0186)

  - An unspecified denial of service. (CVE-2010-0187)");
  script_set_attribute(attribute:"see_also",value:"http://www.adobe.com/support/security/bulletins/apsb10-06.html");
  script_set_attribute(attribute:"solution",value:"Upgrade to Adobe AIR 1.5.3.9130 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_air_installed.nasl");
  script_require_keys("SMB/Adobe_AIR/Version");
  exit(0);
}

include("global_settings.inc");

version_ui = get_kb_item("SMB/Adobe_AIR/Version_UI");
version = get_kb_item("SMB/Adobe_AIR/Version");
if (isnull(version)) exit(1, "The 'SMB/Adobe_AIR/Version' KB item is missing.");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 5 ||
      (
        ver[1] == 5 && 
        (
          ver[2] < 3 ||
          (ver[2] == 3 && ver[3] < 9130)
        )
      )
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n' +
      'Adobe AIR ' + version_report + ' is currently installed on the remote host.\n';
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The Adobe AIR "+version_report+" install is not affected.");

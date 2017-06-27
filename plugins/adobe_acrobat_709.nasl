#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40798);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2006-5857", "CVE-2007-0044", "CVE-2007-0045", "CVE-2007-0046",
                "CVE-2007-0047", "CVE-2007-0048");
  script_bugtraq_id(21858, 21981);
  script_osvdb_id(31046, 31047, 31048, 31316, 31596, 34407);

  script_name(english:"Adobe Acrobat < 6.0.6 / 7.0.9 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat on the remote Windows host is affected by
multiple vulnerabilities." );

  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote host is earlier
than 6.0.6 / 7.0.9 / 8.0 and thus reportedly is affected by several
security issues, including one that can lead to arbitrary code
execution when processing a malicious PDF file." );

 script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb07-01.html"
  );

  script_set_attribute(
    attribute:"solution",
    value: "Upgrade to Adobe Acrobat 6.0.6 / 7.0.9 / 8.0 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(352, 399);

  script_set_attribute( attribute:'vuln_publication_date', value:'2007/01/04' );
  script_set_attribute( attribute:'patch_publication_date', value:'2007/01/09' );
  script_set_attribute( attribute:'plugin_publication_date', value:'2009/08/28' );

 script_cvs_date("$Date: 2016/11/11 19:58:27 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Acrobat/Version");

  exit(0);
}

include("global_settings.inc");

version = get_kb_item("SMB/Acrobat/Version");
if (isnull(version)) exit(1, "The 'SMB/Acrobat/Version' KB item is missing.");

if (version =~ "^([0-5]\.|6\.0\.[0-5][^0-9.]?|7\.0\.[0-8][^0-9.]?)")
{
  version_ui = get_kb_item("SMB/Acrobat/Version_UI");
  if (report_verbosity > 0 && version_ui)
  {
    path = get_kb_item("SMB/Acrobat/Path");
    if (isnull(path)) path = "n/a";

    report = string(
      "\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version_ui, "\n",
      "  Fix               : 6.0.6 / 7.0.9 / 8.0\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "Acrobat "+version+" is not affected.");

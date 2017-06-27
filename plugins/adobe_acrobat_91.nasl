#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(40803);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2009-0193", "CVE-2009-0658", "CVE-2009-0927",
                "CVE-2009-0928", "CVE-2009-1061", "CVE-2009-1062");
  script_bugtraq_id(33751, 34169, 34229);
  script_osvdb_id(52073, 53644, 53645, 53646, 53647, 53648);
  script_xref(name:"TRA", value:"TRA-2009-01");
  script_xref(name:"EDB-ID", value:"8099");
  script_xref(name:"Secunia", value:"33901");

  script_name(english:"Adobe Acrobat < 9.1 / 8.1.4 / 7.1.1 Multiple Vulnerabilities");
  script_summary(english:"Check version of Adobe Acrobat");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat on the remote Windows host is affected by
multiple vulnerabilities."  );

  script_set_attribute(
    attribute:"description", 
    value:
"The version of Adobe Acrobat installed on the remote host is earlier
than 9.1 / 8.1.4 / 7.1.1.  Such versions are reportedly affected by
multiple vulnerabilities :

  - An integer buffer overflow can be triggered when
    processing a malformed JBIG2 image stream with the
    '/JBIG2Decode' filter. (CVE-2009-0658)

  - A vulnerability in the 'getIcon()' JavaScript method of
    a Collab object could allow for remote code execution.
    (CVE-2009-0927)

  - Additional vulnerabilities involving handling of JBIG2
    image streams could lead to remote code execution.
    (CVE-2009-0193, CVE-2009-0928, CVE-2009-1061,
    CVE-2009-1062)

If an attacker can trick a user into opening a specially crafted PDF
file, he can exploit these flaws to execute arbitrary code subject to
the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2009-01");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb09-03.html"
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb09-04.html"
  );

  script_set_attribute(
    attribute:"solution",
    value: "Upgrade to Adobe Acrobat 9.1 / 8.1.4 / 7.1.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Collab.getIcon() Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 119);

  script_set_attribute( attribute:'vuln_publication_date', value:'2009/03/18' );
  script_set_attribute( attribute:'patch_publication_date', value:'2009/03/18' );
  script_set_attribute( attribute:'plugin_publication_date', value:'2009/08/28' );

 script_cvs_date("$Date: 2016/11/11 19:58:28 $");
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

if (
  version =~ "^[0-6]\." ||
  version =~ "^7\.(0\.|1\.0\.)" ||
  version =~ "^8\.(0\.|1\.[0-3]\.)" ||
  version =~ "^9\.0\."
)
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
      "  Fix               : 9.1 / 8.1.4 / 7.1.1\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "Acrobat "+version+" is not affected.");

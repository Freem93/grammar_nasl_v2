#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");


if (description)
{
  script_id(40805);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2009-0198", "CVE-2009-0509", "CVE-2009-0510", "CVE-2009-0511", "CVE-2009-0512",
                "CVE-2009-0888", "CVE-2009-0889", "CVE-2009-1855", "CVE-2009-1856", "CVE-2009-1857",
                "CVE-2009-1858", "CVE-2009-1859", "CVE-2009-1861");
  script_bugtraq_id(35274, 35282, 35289, 35291, 35293, 35294, 35295,
                    35296, 35298, 35299, 35300, 35301, 35302, 35303);
  script_osvdb_id(
    56106,
    56107,
    56108,
    56109,
    56110,
    56111,
    56112,
    56113,
    56114,
    56115,
    56116,
    56117,
    56118
  );

  script_name(english:"Adobe Acrobat < 9.1.2 / 8.1.6 / 7.1.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat on the remote Windows host is affected by
multiple vulnerabilities."  );
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote host is earlier
than 9.1.2 / 8.1.6 / 7.1.3.  Such versions are reportedly affected by
multiple vulnerabilities :

  - A stack-based buffer overflow can lead to code
    execution. (CVE-2009-1855)

  - An integer buffer overflow can result in an application
    crash and possibly code execution, although that has
    not been shown yet. (CVE-2009-1856)

  - A memory corruption issue can result in an application
    crash and possibly code execution, although that has
    not been shown yet. (CVE-2009-1857)

  - A memory corruption issue in the JBIG2 filter can lead
    to code execution. (CVE-2009-1858)

  - A memory corruption issue can lead to code execution.
    (CVE-2009-1859)

  - A memory corruption issue in the JBIG2 filter can
    result in an application crash and possibly code
    execution, although that has not been shown yet.
    (CVE-2009-0198)

  - Multiple heap buffer overflow vulnerabilities in the
    JBIG2 filter can lead to code execution.
    (CVE-2009-0509, CVE-2009-0510, CVE-2009-0511,
    CVE-2009-0512, CVE-2009-0888, CVE-2009-0889)

  - Multiple heap-based buffer overflow vulnerabilities can
    lead to code execution. (CVE-2009-1861)"  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb09-07.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Adobe Acrobat 9.1.2 / 8.1.6 / 7.1.3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute( attribute:'vuln_publication_date', value:'2009/06/09' );
  script_set_attribute( attribute:'patch_publication_date', value:'2009/06/09' );
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

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 7 ||
  (
    ver[0] == 7 &&
    (
      ver[1] < 1 ||
      (ver[1] == 1 && ver[2] < 3)
    )
  ) ||
  (
    ver[0] == 8 &&
    (
      ver[1] < 1 ||
      (ver[1] == 1 && ver[2] < 6)
    )
  ) ||
  (
    ver[0] == 9 &&
    (
      ver[1] < 1 ||
      (ver[1] == 1 && ver[2] < 2)
    )
  )
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
      "  Fix               : 9.1.2 / 8.1.6 / 7.1.3\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "Acrobat "+version+" is not affected.");

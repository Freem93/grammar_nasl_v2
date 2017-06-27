#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44597);
  script_version("$Revision: 1.13 $");

  script_cve_id(
    "CVE-2006-4339", 
    "CVE-2009-0217", 
    "CVE-2009-2493", 
    "CVE-2009-2949", 
    "CVE-2009-2950", 
    "CVE-2009-3301", 
    "CVE-2009-3302"
  );
  script_bugtraq_id(19849, 35671, 35828, 38218);
  script_osvdb_id(28549, 56243, 56698, 62382, 62383, 62384, 62385);

  script_name(english:"Sun OpenOffice.org < 3.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Sun OpenOffice.org.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a program affected by multiple buffer
overflows."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Sun Microsystems OpenOffice.org installed on the
remote host is prior to version 3.2. It is, therefore, affected by
several issues :

  - Signatures may not be handled properly due to a
    vulnerability in the libxml2 library. (CVE-2006-4339)

  - There is an HMAC truncation authentication bypass
    vulnerability in the libxmlsec library. (CVE-2009-0217)

  - The application is bundled with a vulnerable version of
    the Microsoft VC++ runtime. (CVE-2009-2493)

  - Specially crafted XPM files are not processed properly,
    which could lead to arbitrary code execution.
    (CVE-2009-2949)

  - Specially crafted GIF files are not processed properly,
    which could lead to arbitrary code execution.
    (CVE-2009-2950)

  - Specially crafted Microsoft Word documents are not
    processed properly, which could lead to arbitrary code
    execution. (CVE-2009-3301 / CVE-2009-3302)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/security/cves/CVE-2006-4339.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/security/cves/CVE-2009-0217.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/security/cves/CVE-2009-2493.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/security/cves/CVE-2009-2949.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/security/cves/CVE-2009-2950.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/security/cves/CVE-2009-3301-3302.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Sun Microsystems OpenOffice.org version 3.2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(94, 119, 189, 264, 310);
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/02/11");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/02/11");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/02/12");
 script_cvs_date("$Date: 2016/12/07 20:46:54 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:openoffice.org");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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
    if (buildid < 9483) 
      security_hole(get_kb_item("SMB/transport"));
    else
     exit(0,"Build " + buildid + " is not affected.");
  }
}
else exit(1, "The 'SMB/OpenOffice/Build' KB item is missing.");

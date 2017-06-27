#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31968);
  script_version("$Revision: 1.14 $");

  script_cve_id(
    "CVE-2007-4770",
    "CVE-2007-4771",
    "CVE-2007-5745",
    "CVE-2007-5746",
    "CVE-2007-5747",
    "CVE-2008-0320"
  );
  script_bugtraq_id(28819);
  script_osvdb_id(41189, 41190, 44469, 44470, 44471, 44472);
  script_xref(name:"Secunia", value:"29852");

  script_name(english:"Sun OpenOffice.org < 2.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Sun OpenOffice.org"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Sun Microsystems OpenOffice.org installed on the
remote host is affected by several issues :

  - Heap overflow and arbitrary code execution
    vulnerabilities involving ODF text documents with 
    XForms (CVE-2007-4770/4771).

  - Heap overflow and arbitrary code execution 
    vulnerabilities involving Quattro Pro files
    (CVE-2007-5745/5747).

  - Heap overflow and arbitrary code execution 
    vulnerabilities involving EMF files (CVE-2007-5746).

  - Heap overflow and arbitrary code execution 
    vulnerabilities involving OLE files (CVE-2008-0320)." );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2007-5746.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2007-4770.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2007-5745.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2008-0320.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Microsystems OpenOffice.org version 2.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'OpenOffice OLE Importer DocumentSummaryInformation Stream Handling Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(119, 189, 399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/17");
 script_cvs_date("$Date: 2016/12/07 20:46:54 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:openoffice.org");
script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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
    if (buildid < 9286) security_hole(get_kb_item("SMB/transport"));
  }
}

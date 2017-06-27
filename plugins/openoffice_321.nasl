#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46814);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/08/24 14:07:49 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-0395");
  script_bugtraq_id(36935, 40599);
  script_osvdb_id(65202, 65203);

  script_name(english:"Oracle OpenOffice.org < 3.2.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of OpenOffice.org");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Oracle OpenOffice.org installed on the remote host is
prior to 3.2.1. It is, therefore, affected by several issues :

  - There is a TLS/SSL renegotiation vulnerability in the
    included third-party OpenSSL library. (CVE-2009-3555)

  - There is a python scripting vulnerability that could 
    lead to undesired code execution when using the 
    OpenOffice scripting IDE. (CVE-2010-0395)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/security/cves/CVE-2009-3555.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/security/cves/CVE-2010-0395.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Oracle OpenOffice.org version 3.2.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(310);
  script_set_attribute(attribute:"vuln_publication_date",value:"2009/11/09");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/06/07");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/06/07");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:openoffice.org");
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
    if (buildid < 9502) 
      security_hole(get_kb_item("SMB/transport"));
    else
     exit(0,"Build " + buildid + " is not affected.");
  }
}
else exit(1, "The 'SMB/OpenOffice/Build' KB item is missing.");

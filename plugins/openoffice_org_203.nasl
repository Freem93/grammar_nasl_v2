#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(21784);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2006-3117", "CVE-2006-2198", "CVE-2006-2199");
  script_bugtraq_id(18737, 18738, 18739);
  script_osvdb_id(26939, 26940, 26941, 26942, 26943, 26944, 26945);

  script_name(english:"OpenOffice < 2.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks for the version of OpenOffice.org");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through OpenOffice.org." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of OpenOffice.org which is older than 
version 2.0.3.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to a user of the 
remote computer and have him open it. The file could be crafted in such a
way that it could exploit a buffer overflow in OpenOffice.org's XML parser,
or by containing rogue macros." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenOffice.org 2.0.3 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2006-2199.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2006-2198.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2006-3117.html" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/30");
 script_cvs_date("$Date: 2016/12/07 20:46:54 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/07/30");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:openoffice.org");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_dependencies("openoffice_installed.nasl");
  script_require_keys("SMB/OpenOffice/Build");
  exit(0);
}

#

build = get_kb_item("SMB/OpenOffice/Build");
if (build)
{
  matches = eregmatch(string:build, pattern:"([0-9]+[a-z][0-9]+)\(Build:([0-9]+)\)");
  if (!isnull(matches))
  {
    buildid = int(matches[2]);
    if (buildid < 9044) security_hole(get_kb_item("SMB/transport"));
  }
}

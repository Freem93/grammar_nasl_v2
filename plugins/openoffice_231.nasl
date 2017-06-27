#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29218);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2007-4575");
  script_bugtraq_id(26703);
  script_osvdb_id(40548);

  script_name(english:"Sun OpenOffice.org < 2.3.1 Database HSQLDB Database Document Handling Arbitrary Java Code Execution");
  script_summary(english:"Checks the version of Sun OpenOffice.org.");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that allows execution of
arbitrary code." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Sun Microsystems
OpenOffice.org that contains an arbitrary code execution vulnerability
in its HSQLDB database engine. If a remote attacker can trick a user
into opening a specially crafted database, this issue can be leveraged
to execute arbitrary static Java code on the remote host subject to
the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2007-4575.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Microsystems OpenOffice.org version 2.3.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/05");
 script_cvs_date("$Date: 2016/05/20 14:21:42 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:openoffice.org");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

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
    if (buildid > 8950 && buildid < 9238) security_hole(get_kb_item("SMB/transport"));
  }
}

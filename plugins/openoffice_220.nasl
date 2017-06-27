#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25004);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2007-0002", "CVE-2007-0238", "CVE-2007-1466");
  script_bugtraq_id(23006, 23067);
  script_osvdb_id(33315, 33972);

  script_name(english:"Sun OpenOffice.org < 2.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Sun OpenOffice.org.");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that may be affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Sun Microsystems
OpenOffice.org that is prior to version 2.2. It is, therefore,
affected by a stack-based buffer overflow vulnerability in its
handling of StarCalc documents. If a remote attacker can trick a user
into opening a specially crafted StarCalc document, the attacker can
execute arbitrary code on the remote host subject to the user's
privileges.

In addition, versions 2.0 - 2.1 reportedly have a heap-based buffer
overflow vulnerability that can be triggered when importing a
specially crafted WordPerfect document, resulting in arbitrary code
execution." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Apr/88" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2007-2.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2007-0238.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2007-0239.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Microsystems OpenOffice.org version 2.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119, 189);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/04/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/03/16");
 script_cvs_date("$Date: 2016/12/07 20:46:54 $");
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
    if (buildid < 9134) security_hole(get_kb_item("SMB/transport"));
  }
}

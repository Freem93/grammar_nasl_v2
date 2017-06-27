#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26064);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-2834");
  script_bugtraq_id(25690);
  script_osvdb_id(40546);

  script_name(english:"Sun OpenOffice.org < 2.3 TIFF Parser Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks the version of Sun OpenOffice.org.");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is affected by multiple
buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Sun Microsystems
OpenOffice.org that is affected by multiple integer overflows in its
TIFF document parser that can be triggered when parsing tags in TIFF
directory entries. If a remote attacker can trick a user into opening
a specially crafted TIFF document, this issue can be leveraged to
execute arbitrary code on the remote host subject to the user's
privileges." );
 # https://labs.idefense.com/verisign/intelligence/2009/vulnerabilities/display.php?id=593
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cb497e7" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/479759/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2007-2834.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Microsystems OpenOffice.org version 2.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(189);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/18");
 script_cvs_date("$Date: 2014/08/27 21:14:41 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:openoffice.org");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

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
    if (buildid < 9221) security_hole(get_kb_item("SMB/transport"));
  }
}

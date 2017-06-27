#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57358);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/17 16:53:08 $");

  script_cve_id("CVE-2011-3666");
  script_bugtraq_id(51139);
  script_osvdb_id(75840, 75841);

  script_name(english:"Firefox 3.6 < 3.6.25 Jar File Enter Key Dialog Bypass (Mac OS X)");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is potentially
affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox 3.6 is earlier than 3.6.25.  Such
versions are potentially affected by a security bypass vulnerability. 

The fix for MFSA-2011-40 was incomplete regarding Java Jar files. The
files were intended to be treated as executables as part of the fix,
but they are not treated as such.");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-59.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 3.6.25 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");
kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'3.6.25', min:'3.6', severity:SECURITY_HOLE);
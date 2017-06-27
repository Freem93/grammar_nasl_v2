#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61519);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/08/14 10:39:30 $");

  script_cve_id("CVE-2012-2498");
  script_bugtraq_id(54847);
  script_osvdb_id(84470);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz29197");

  script_name(english:"Mac OS X : Cisco AnyConnect Secure Mobility Client 3.1 < 3.1(495) MiTM");
  script_summary(english:"Checks version of Cisco AnyConnect Client");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is vulnerable to
man-in-the-middle attacks."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Cisco AnyConnect 3.1 prior to
3.1(495).  As such, it prompts the user to decide whether or not to
proceed when an untrusted certificate is seen.  Accepting an untrusted
certificate could result in a man-in-the-middle attack."
  );
  # http://tools.cisco.com/Support/BugToolKit/search/getBugDetails.do?method=fetchBugDetails&bugId=CSCtz29197
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b24acefb");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Cisco AnyConnect Secure Mobility Client 3.1(495) or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("macosx_cisco_anyconnect_installed.nasl");
  script_require_keys("MacOSX/Cisco_AnyConnect/Installed");
  
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = 'Cisco AnyConnect Mobility VPN Client';

kb_base = "MacOSX/Cisco_AnyConnect";
get_kb_item_or_exit(kb_base+"/Installed");
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);

fix = '3.1.495.0';
fix_display = fix + ' (3.1(495))';

if (version =~ "^3\.1" && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix_display + '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71860);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/03 17:40:03 $");

  script_cve_id("CVE-2013-4063", "CVE-2013-4064", "CVE-2013-4065");
  script_bugtraq_id(64444, 64445, 64451);
  script_osvdb_id(101172, 101173, 101174);

  script_name(english:"IBM Domino 8.5.x < 8.5.3 FP6 iNotes Multiple XSS (credentialed check)");
  script_summary(english:"Checks version of IBM Domino");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by multiple
cross-site scripting vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of IBM Domino (formerly Lotus Domino)
8.5.x prior to 8.5.3 Fix Pack 6 installed.  It is, therefore, reportedly
affected by the following iNotes-related cross-site scripting
vulnerabilities :

  - An input validation error exists related to handling
    content in email messages. (CVE-2013-4063)

  - An input validation error exists related to iNotes when
    running in 'ultra-light' mode. (CVE-2013-4064)

  - An input validation error exists related to handling
    content in email messages and iNotes when running in
    'ultra-light' mode. (CVE-2013-4065)"
  );
  # Fix pack downloads
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24032242#FP6");
  # 8.5.3 FP6 release notes
  # http://www-10.lotus.com/ldd/fixlist.nsf/8d1c0550e6242b69852570c900549a74/2ca7aa993e50ba8285257c1d006472bd?OpenDocument
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc8b4137");
  script_set_attribute(attribute:"solution", value:"Upgrade to IBM Domino 8.5.3 FP6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("lotus_domino_installed.nasl");
  script_require_keys("SMB/Domino/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "IBM Domino";
kb_base = "SMB/Domino/";

port = get_kb_item('SMB/transport');
if (isnull(port)) port = 445;
version = get_kb_item_or_exit(kb_base + 'Version');
path = get_kb_item_or_exit(kb_base + 'Path');

fix = '8.5.36.13325';
lower_cutoff = '8.5.0.0';

if (
  ver_compare(ver:version, fix:lower_cutoff, strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fix, strict:FALSE) < 0
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + ' (8.5.3 FP6)' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);

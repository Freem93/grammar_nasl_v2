#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71040);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/11/22 12:22:47 $");

  script_cve_id("CVE-2013-3694", "CVE-2013-6798");
  script_bugtraq_id(63695, 63774);
  script_osvdb_id(99697, 99950);

  script_name(english:"BlackBerry Link Multiple Vulnerabilities");
  script_summary(english:"Checks version of BlackBerry Link");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of BlackBerry Link installed that is
prior to version 1.2.1.31.  Such versions are affected by multiple
vulnerabilities :

  - A WebDAV server that listens on an IPv6 address allows
    remote access to the host's file system.  It may also
    be possible to utilize this vulnerability via a DNS
    rebinding attack to execute arbitrary code by tricking
    a user into opening a specially crafted page.
    (CVE-2013-3694)

  - A flaw in Peer Manager on Mac OS X may allow
    context-dependent attackers to bypass access
    restrictions on remote file-access folders for WebDAV
    requests. (CVE-2013-6798)"
  );
  # http://btsc.webapps.blackberry.com/btsc/viewdocument.do?externalId=KB35315&sliceId=1&cmd=displayKC&docType=kc&noCount=true&ViewedDocsListHelper=com.kanisa.apps.common.BaseViewedDocsListHelperImpl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?098d279b");
  script_set_attribute(attribute:"see_also", value:"http://blog.cmpxchg8b.com/2013/11/qnx.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to BlackBerry Link 1.2.1.31.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:blackberry:blackberry_link");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("blackberry_link_installed.nbin");
  script_require_keys("SMB/blackberry_link/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/blackberry_link/";
appname = "BlackBerry Link";

path = get_kb_item_or_exit(kb_base + "Path");
version  = get_kb_item_or_exit(kb_base + "Version");

lower_bound = "1.0.1.12";
fix = "1.2.1.31";

if (
  ver_compare(ver:version, fix:lower_bound, strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1
)
{
  set_kb_item(name:"www/0/XSRF", value:TRUE);

  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);

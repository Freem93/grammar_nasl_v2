#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51343);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/02/09 20:40:56 $");

  script_cve_id(
    "CVE-2010-4579","CVE-2010-4580","CVE-2010-4581","CVE-2010-4582",
    "CVE-2010-4583","CVE-2010-4584","CVE-2010-4585","CVE-2010-4586",
    "CVE-2010-4587"
  );
  script_bugtraq_id(45461);
  script_osvdb_id(
    70004,
    70005,
    70006,
    70007,
    70008,
    70009,
    70010,
    70011,
    70012
  );
  script_xref(name:"Secunia", value:"42653");

  script_name(english:"Opera < 11 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than
11.00.  Such versions are potentially affected by the following 
issues :

  - An error exists such that web page content can be
    displayed over dialog boxes leading to security
    warning misrepresentation. (977, CVE-2010-4579)

  - An error exists such that WAP form contents can be 
    leaked to third-party sites. (979, CVE-2010-4580)

  - An unspecified high severity issue with unknown
    impact exists. (CVE-2010-4581)

  - An error exists in the handling of security policies
    during extension updates. (CVE-2010-4582)

  - An error exists when 'Opera Turbo' is enabled that 
    does not display a page's security information 
    correctly. (CVE-2010-4583)

  - An error exists when viewing sites over HTTPS such that
    problems with X.509 certificates are not displayed
    properly. (CVE-2010-4584)

  - An error exists in the automatic update functionality 
    that allows an attacker to cause a denial of service
    by crashing the application. (CVE-2010-4585)

  - The 'WebSockets' implementation contains unspecified 
    errors with unknown impact. (CVE-2010-4586)

  - An error exists in the implementation of the 'Insecure 
    Third Party Module' warning messages that results in an 
    unspecified vulnerability. (CVE-2010-4587)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1100/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/977/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/979/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 11 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/17");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Opera/Version");

version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

install_path = get_kb_item("SMB/Opera/Path");

if (ver_compare(ver:version, fix:'11.0.1156.0') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : 11.00\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(port:get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Opera "+version_report+" is installed.");

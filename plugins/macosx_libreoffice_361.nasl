#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73333);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/04/04 18:52:06 $");

  script_cve_id("CVE-2012-4233");
  script_bugtraq_id(56352);
  script_osvdb_id(86848, 86849, 86852, 86853);

  script_name(english:"LibreOffice < 3.5.7 / 3.6.1 Multiple Denial of Service Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of LibreOffice");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"A version of LibreOffice prior to 3.5.7 / 3.6.1 is installed on the
remote Mac OS X host. It is, therefore, reportedly affected by
multiple denial of service vulnerabilities in various import filters:

  - Excel (.xls)

  - Windows Meta File (.wmf)

  - Open Document Format (.odg / .odt)

This could allow a remote attacker with a specially crafted file to
crash the application upon loading.

Note that Nessus has not attempted to exploit these issues, but has
instead relied only on the self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.libreoffice.org/about-us/security/advisories/cve-2012-4233/");
  # http://blog.documentfoundation.org/2012/10/18/the-document-foundation-announces-libreoffice-3-5-7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef8de15a");
  # http://blog.documentfoundation.org/2012/08/29/the-document-foundation-announces-libreoffice-3-6-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3af5545");
  script_set_attribute(attribute:"solution", value:"Upgrade to LibreOffice version 3.5.7 / 3.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_dependencies("macosx_libreoffice_installed.nasl");
  script_require_keys("MacOSX/LibreOffice/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "MacOSX/LibreOffice";
get_kb_item_or_exit(kb_base+"/Installed");
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);

if (
  # nb: first release of LibreOffice was 3.3.0.
  version =~ "^3\.[3-4]\." ||
  (version =~ "^3\.5\." && ver_compare(ver:version, fix:'3.5.7', strict:FALSE) == -1) ||
  (version =~ "^3\.6\." && ver_compare(ver:version, fix:'3.6.1.1', strict:FALSE) == -1)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.5.7 / 3.6.1\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "LibreOffice", version, path);

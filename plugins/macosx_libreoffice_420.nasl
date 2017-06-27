#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73337);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/07/10 14:11:55 $");

  script_cve_id("CVE-2013-1752", "CVE-2013-4238");
  script_osvdb_id(
    96215,
    101381,
    101382,
    101383,
    101384,
    101385,
    101386
  );

  script_name(english:"LibreOffice < 4.1.5 / 4.2.0 Python Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of LibreOffice");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities with Python.");
  script_set_attribute(attribute:"description", value:
"A version of LibreOffice prior to 4.1.5 / 4.2.0 is installed on the
remote Mac OS X host. It is, therefore, reportedly affected by
multiple vulnerabilities including a denial of service vulnerability
related to Python.

A remote attacker could use these flaws to cause a denial of service
or to conduct spoofing attacks.

Note that Nessus has not attempted to exploit these issues, but has
instead relied only on the self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.libreoffice.org/about-us/security/advisories/cve-2013-1752/");
  # http://blog.documentfoundation.org/2014/02/11/the-document-foundation-announces-libreoffice-4-1-5/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc6741ee");
  # http://blog.documentfoundation.org/2014/01/30/libreoffice-4-2-focusing-on-performance-and-interoperability-and-improving-the-integration-with-microsoft-windows/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a594575e");
  script_set_attribute(attribute:"solution", value:"Upgrade to LibreOffice version 4.1.5 / 4.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
  version =~ "^3" ||
  (version =~ "^4\.1\." && ver_compare(ver:version, fix:'4.1.5.1', strict:FALSE) == -1) ||
  (version =~ "^4\.2\." && ver_compare(ver:version, fix:'4.2.0.1', strict:FALSE) == -1)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.1.5 / 4.2.0\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "LibreOffice", version, path);

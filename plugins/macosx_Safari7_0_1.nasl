#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71498);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/07/03 13:25:44 $");

  script_cve_id(
    "CVE-2013-2909",
    "CVE-2013-5195",
    "CVE-2013-5196",
    "CVE-2013-5197",
    "CVE-2013-5198",
    "CVE-2013-5199",
    "CVE-2013-5225",
    "CVE-2013-5227",
    "CVE-2013-5228"
  );
  script_bugtraq_id(
    64353,
    64354,
    64355,
    64356,
    64358,
    64359,
    64360,
    64361,
    64362
  );
  script_osvdb_id(
    101089,
    101090,
    101091,
    101092,
    101093,
    101094,
    101095,
    101096,
    97970
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-12-16-1");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-12-16-2");

  script_name(english:"Mac OS X : Apple Safari < 6.1.1 / 7.0.1 Multiple Vulnerabilities");
  script_summary(english:"Check the Safari SourceVersion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by several
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apple Safari installed on the remote Mac OS X host is
prior to 6.1.1 or 7.0.1. It is, therefore, potentially affected by
several issues :

  - A use-after-free error exists related to 'inline-block'
    rendering. (CVE-2013-2909)

  - Multiple, unspecified memory corruption vulnerabilities
    exist in WebKit that could lead to unexpected program
    termination or arbitrary code execution. (CVE-2013-5195,
    CVE-2013-5196, CVE-2013-5197, CVE-2013-5198,
    CVE-2013-5199, CVE-2013-5225, CVE-2013-5228)

  - Multiple information disclosure vulnerabilities exist
    due to an origin-validation error in which user
    information is auto-filled into a sub-frame from a
    different domain. (CVE-2013-5227)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-286/");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6082");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6084");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/530366/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/530369/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"For Mac OS X 10.9, upgrade to 10.9.1, which includes Apple Safari
7.0.1. Otherwise, upgrade to Apple Safari 6.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

if (!ereg(pattern:"Mac OS X 10\.[7-9]([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.7 / 10.8 / 10.9");

get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

if ("10.7" >< os || "10.8" >< os) fixed_version = "6.1.1";
else fixed_version = "7.0.1";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);

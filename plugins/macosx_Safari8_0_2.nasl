#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80055);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/07/03 13:25:44 $");

  script_cve_id(
    "CVE-2014-4465",
    "CVE-2014-4471",
    "CVE-2014-4473",
    "CVE-2014-4472",
    "CVE-2014-4474",
    "CVE-2014-4475",
    "CVE-2014-4466",
    "CVE-2014-4468",
    "CVE-2014-4469",
    "CVE-2014-4470",
    "CVE-2014-1748"
  );
  script_bugtraq_id(
    71439,
    71438,
    71444,
    71442,
    71449,
    71451,
    71445,
    71459,
    71461,
    71462,
    71464
  );
  script_osvdb_id(
    115354,
    115349,
    115351,
    115350,
    115352,
    115353,
    115345,
    115346,
    115347,
    115348,
    107144
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-12-3-1");

  script_name(english:"Mac OS X : Apple Safari < 6.2.2 / 7.1.2 / 8.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X host is a
version prior to 6.2.2 / 7.1.2 / 8.0.2. It is, therefore, affected by
the following vulnerabilities in WebKit :

  - An SVG loaded in an IMG element could load a CSS file
    cross-origin. This can allow data exfiltration.
    (CVE-2014-4465)

  - A UI spoofing flaw exists in the handling of scrollbar
    boundaries. Visiting websites that frame malicious
    content can allow the UI to be spoofed. (CVE-2014-1748)

  - Multiple memory corruption issues exist that can lead to
    an unexpected application crash or potential arbitrary
    code execution by means of malicious website content.
    (CVE-2014-4452, CVE-2014-4459, CVE-2014-4466,
    CVE-2014-4468, CVE-2014-4469, CVE-2014-4470,
    CVE-2014-4471, CVE-2014-4472, CVE-2014-4473,
    CVE-2014-4474, CVE-2014-4475)

Note that the 6.2.2 / 7.1.2 / 8.0.2 Safari updates include the
security content of the 6.2.1 / 7.1.1 / 8.0.1 updates. These more
recent updates, however, were released to fix potential issues with
the installation of the previous patch release.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/en-us/HT1222");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/534148");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/en-us/HT6597");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 6.2.2 / 7.1.2 / 8.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

if (!ereg(pattern:"Mac OS X 10\.([89]|10)([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.8 / 10.9 / 10.10");

get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

# Even though the fixes that the recent
# patches replace are no longer availabe,
# the older versions are checked to avoid
# FPs in the event that the initial fix
# is present
if ("10.8" >< os)
{
  cutoff = "6.2.1";
  fixed_version = "6.2.2";
}
else if ("10.9" >< os)
{
  cutoff = "7.1.1";
  fixed_version = "7.1.2";
}
else
{
  cutoff= "8.0.1";
  fixed_version = "8.0.2";
}

if (ver_compare(ver:version, fix:cutoff, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);

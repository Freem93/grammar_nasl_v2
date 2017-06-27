#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87370);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:10 $");

  script_cve_id(
    "CVE-2015-7048",
    "CVE-2015-7095",
    "CVE-2015-7096",
    "CVE-2015-7097",
    "CVE-2015-7098",
    "CVE-2015-7099",
    "CVE-2015-7100",
    "CVE-2015-7101",
    "CVE-2015-7102",
    "CVE-2015-7103",
    "CVE-2015-7104",
    "CVE-2015-7050"
  );
  script_bugtraq_id(
    78720,
    78722,
    78726
  );
  script_osvdb_id(
    131370,
    131371,
    131372,
    131373,
    131374,
    131375,
    131376,
    131377,
    131378,
    131379,
    131380,
    131440
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-12-08-5");

  script_name(english:"Mac OS X : Apple Safari < 9.0.2 Multiple RCE");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote host is prior to
9.0.2. It is, therefore, affected by multiple memory corruption issues
in WebKit due to improper memory handling. An unauthenticated, remote
attacker can exploit these, via a crafted website, to execute
arbitrary code or possibly cause a denial of service.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205639");
  # http://lists.apple.com/archives/security-announce/2015/Dec/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea90039a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 9.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

if (!ereg(pattern:"Mac OS X 10\.(9|10|11)([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.9 / 10.10 / 10.11");

installed = get_kb_item_or_exit("MacOSX/Safari/Installed", exit_code:0);
path    = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "9.0.2";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);

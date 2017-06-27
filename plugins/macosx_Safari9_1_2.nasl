#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92358);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/08/29 13:57:36 $");

  script_cve_id(
    "CVE-2016-4583",
    "CVE-2016-4584",
    "CVE-2016-4585",
    "CVE-2016-4586",
    "CVE-2016-4589",
    "CVE-2016-4590",
    "CVE-2016-4591",
    "CVE-2016-4592",
    "CVE-2016-4622",
    "CVE-2016-4623",
    "CVE-2016-4624",
    "CVE-2016-4651"
  );
  script_osvdb_id(
    141654,
    141655,
    141656,
    141657,
    141658,
    141659,
    141660,
    141661,
    141662,
    141663,
    141664,
    141665
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-07-18-5");

  script_name(english:"Mac OS X : Apple Safari < 9.1.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X host is
prior to 9.1.2. It is, therefore, affected by multiple
vulnerabilities, the most serious of which can result in remote code
execution, in the following components :

  - WebKit
  - WebKit JavaScript Bindings
  - WebKit Page Loading");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT206900");
  # https://lists.apple.com/archives/security-announce/2016/Jul/msg00004.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?350c3f83");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 9.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

fixed_version = "9.1.2";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  report = report_items_str(
    report_items:make_array(
      "Path", path,
      "Installed version", version,
      "Fixed version", fixed_version
    ),
    ordered_fields:make_list("Path", "Installed version", "Fixed version")
  );
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report, xss:TRUE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);

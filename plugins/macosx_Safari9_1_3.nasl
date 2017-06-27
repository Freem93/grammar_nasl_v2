#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93593);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id("CVE-2016-4657");
  script_bugtraq_id(92653);
  script_osvdb_id(143464);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-09-01-1");

  script_name(english:"Mac OS X : Apple Safari < 9.1.3 WebKit Memory Corruption RCE");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote host is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X host is
prior to 9.1.3. It is, therefore, affected by a remote code execution
vulnerability in WebKit due to a memory corruption issue. An
unauthenticated, remote attacker can exploit this, by convincing a
user to visit a malicious website, to cause a denial of service
condition or execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207131");
  # http://lists.apple.com/archives/security-announce/2016/Sep/msg00000.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dade65f4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 9.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

fixed_version = "9.1.3";

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
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);

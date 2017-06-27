#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94915);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id("CVE-2016-4613", "CVE-2016-7578");
  script_bugtraq_id(93949);
  script_osvdb_id(146224, 146369);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-10-27-3");

  script_name(english:"Apple iTunes < 12.5.2 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of iTunes on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
prior to 12.5.2. It is, therefore, affected by multiple
vulnerabilities :

  - A cross-origin bypass vulnerability exists in WebKit due
    to improper handling of the location attribute. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a maliciously crafted
    website, to bypass cross-origin policies and disclose
    sensitive user data. (CVE-2016-4613)

  - Multiple memory corruption errors exist in WebKit due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these
    issues, by convincing a user to visit a maliciously
    crafted website, to execute arbitrary code.
    (CVE-2016-7578)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207274");
  # http://lists.apple.com/archives/security-announce/2016/Oct/msg00007.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b09fd5a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("installed_sw/iTunes Version", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# Ensure this is Windows
get_kb_item_or_exit("SMB/Registry/Enumerated");

app_id = 'iTunes Version';
install = get_single_install(app_name:app_id, exit_if_unknown_ver:TRUE);

version = install["version"];
path = install["path"];

fixed_version = "12.5.2";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  order = make_list('Version source', 'Installed version', 'Fixed version');
  report = make_array(
    order[0], path,
    order[1], version,
    order[2], fixed_version
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "iTunes", version, path);

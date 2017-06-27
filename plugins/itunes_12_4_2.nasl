#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92410);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/07/21 13:58:10 $");

  script_cve_id(
    "CVE-2016-1684",
    "CVE-2016-1836",
    "CVE-2016-4447",
    "CVE-2016-4448",
    "CVE-2016-4449",
    "CVE-2016-4483",
    "CVE-2016-4607",
    "CVE-2016-4608",
    "CVE-2016-4609",
    "CVE-2016-4610",
    "CVE-2016-4612",
    "CVE-2016-4614",
    "CVE-2016-4615",
    "CVE-2016-4616",
    "CVE-2016-4619"
  );
  script_bugtraq_id(
    90013,
    90856,
    90864,
    90865,
    90876
  );
  script_osvdb_id(
    137965,
    138568,
    138926,
    138928,
    138966,
    139032,
    141617,
    141618,
    141619,
    141620,
    141621,
    141622,
    141623,
    141624,
    141625
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-07-18-6");

  script_name(english:"Apple iTunes < 12.4.2 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of iTunes on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
prior to 12.4.2. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple memory corruption issues exist in the libxslt
    component due to improper validation of user-supplied
    input. An unauthenticated, remote attacker can exploit
    this to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2016-1684,
    CVE-2016-4607, CVE-2016-4608, CVE-2016-4609,
    CVE-2016-4610, CVE-2016-4612)

  - Multiple memory corruption issues exist in the libxml2
    component that allow a remote attacker to cause a denial
    of service condition or the execution of arbitrary code.
    (CVE-2016-1836, CVE-2016-4447, CVE-2016-4448,
    CVE-2016-4483, CVE-2016-4614, CVE-2016-4615,
    CVE-2016-4616, CVE-2016-4619)

  - An XXE (Xml eXternal Entity) injection vulnerability
    exists in the libxml2 component due to an incorrectly
    configured XML parser accepting XML external entities
    from an untrusted source. A remote attacker can exploit
    this, via a specially crafted XML file, to disclose
    arbitrary files and user information. (CVE-2016-4449)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT206901");
  # http://prod.lists.apple.com/archives/security-announce/2016/Jul/msg00005.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b41b5aa");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

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

fixed_version = "12.4.2";

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

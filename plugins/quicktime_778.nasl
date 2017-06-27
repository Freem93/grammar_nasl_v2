#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85662);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/01/17 15:50:10 $");

  script_cve_id(
    "CVE-2015-3788",
    "CVE-2015-3789",
    "CVE-2015-3790",
    "CVE-2015-3791",
    "CVE-2015-3792",
    "CVE-2015-5751",
    "CVE-2015-5779",
    "CVE-2015-5785",
    "CVE-2015-5786"
  );
  script_bugtraq_id(
    76340,
    76443,
    76444
  );
  script_osvdb_id(
    126244,
    126246,
    126247,
    126248,
    126249,
    126250,
    126251,
    126533,
    126534
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-08-20-1");

  script_name(english:"Apple QuickTime < 7.7.8 Multiple Arbitrary Code Vulnerabilities (Windows)");
  script_summary(english:"Checks the version of QuickTime on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple arbitrary code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple QuickTime installed on the remote Windows host is
prior to 7.7.8. It is, therefore, affected by multiple arbitrary code
execution vulnerabilities :

  - A memory corruption issue exists due to improper
    validation of user-supplied input when handling URL atom
    sizes. A remote attacker can exploit this issue by
    convincing a user to open a specially crafted file,
    resulting in the execution of arbitrary code in the
    context of the current user. (CVE-2015-3788)

  - A memory corruption issue exists due to improper
    validation of user-supplied input when handling 3GPP
    STSD sample description entry sizes. A remote attacker
    can exploit this issue by convincing a user to open a
    specially crafted file, resulting in the execution of
    arbitrary code in the context of the current user.
    (CVE-2015-3789)

  - A memory corruption issue exists due to improper
    validation of user-supplied input when handling MVHD
    atom sizes. A remote attacker can exploit this issue by
    convincing a user to open a specially crafted file,
    resulting in the execution of arbitrary code in the
    context of the current user. (CVE-2015-3790)

  - A memory corruption issue exists due to improper
    validation of user-supplied input when handling
    mismatching ESDS atom descriptor type lengths. A remote
    attacker can exploit this issue by convincing a user to
    open a specially crafted file, resulting in the
    execution of arbitrary code in the context of the
    current user. (CVE-2015-3791)

  - A memory corruption issue exists due to improper
    validation of user-supplied input when handling
    MDAT sections. A remote attacker can exploit this issue
    by convincing a user to open a specially crafted file,
    resulting in the execution of arbitrary code in the
    context of the current user. (CVE-2015-3792)

  - An unspecified memory corruption issue exists due to
    improper validation of user-supplied input. A remote
    attacker can exploit this issue by convincing a user to
    open a specially crafted file, resulting in the
    execution of arbitrary code in the context of the
    current user. (CVE-2015-5751)

  - An unspecified memory corruption issue exists due to
    improper validation of user-supplied input. A remote
    attacker can exploit this issue by convincing a user to
    open a specially crafted file, resulting in the
    execution of arbitrary code in the context of the
    current user. (CVE-2015-5779)

  - An unspecified memory corruption issue exists due to
    improper validation of user-supplied input. A remote
    attacker can exploit this issue by convincing a user to
    open a specially crafted file, resulting in the
    execution of arbitrary code in the context of the
    current user. (CVE-2015-5785)

  - An unspecified memory corruption issue exists due to
    improper validation of user-supplied input. A remote
    attacker can exploit this issue by convincing a user to
    open a specially crafted file, resulting in the
    execution of arbitrary code in the context of the
    current user. (CVE-2015-5786)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205046");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple QuickTime 7.7.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/QuickTime/";

version = get_kb_item_or_exit(kb_base+"Version");
path = get_kb_item_or_exit(kb_base+"Path");

version_ui = get_kb_item(kb_base+"Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

fixed_version = "7.78.80.95";
fixed_version_ui = "7.7.8 (1680.95.71)";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fixed_version_ui +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, 'QuickTime Player', version_report, path);

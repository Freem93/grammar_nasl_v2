#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86001);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/04 15:52:09 $");

  script_cve_id(
    "CVE-2010-3190",
    "CVE-2014-8146",
    "CVE-2015-1152",
    "CVE-2015-1153",
    "CVE-2015-1157",
    "CVE-2015-1205",
    "CVE-2015-3686",
    "CVE-2015-3687",
    "CVE-2015-3688",
    "CVE-2015-3730",
    "CVE-2015-3731",
    "CVE-2015-3733",
    "CVE-2015-3734",
    "CVE-2015-3735",
    "CVE-2015-3736",
    "CVE-2015-3737",
    "CVE-2015-3738",
    "CVE-2015-3739",
    "CVE-2015-3740",
    "CVE-2015-3741",
    "CVE-2015-3742",
    "CVE-2015-3743",
    "CVE-2015-3744",
    "CVE-2015-3745",
    "CVE-2015-3746",
    "CVE-2015-3747",
    "CVE-2015-3748",
    "CVE-2015-3749",
    "CVE-2015-5755",
    "CVE-2015-5761",
    "CVE-2015-5789",
    "CVE-2015-5790",
    "CVE-2015-5791",
    "CVE-2015-5792",
    "CVE-2015-5793",
    "CVE-2015-5794",
    "CVE-2015-5795",
    "CVE-2015-5796",
    "CVE-2015-5797",
    "CVE-2015-5798",
    "CVE-2015-5799",
    "CVE-2015-5800",
    "CVE-2015-5801",
    "CVE-2015-5802",
    "CVE-2015-5803",
    "CVE-2015-5804",
    "CVE-2015-5805",
    "CVE-2015-5806",
    "CVE-2015-5807",
    "CVE-2015-5808",
    "CVE-2015-5809",
    "CVE-2015-5810",
    "CVE-2015-5811",
    "CVE-2015-5812",
    "CVE-2015-5813",
    "CVE-2015-5814",
    "CVE-2015-5815",
    "CVE-2015-5816",
    "CVE-2015-5817",
    "CVE-2015-5818",
    "CVE-2015-5819",
    "CVE-2015-5821",
    "CVE-2015-5822",
    "CVE-2015-5823",
    "CVE-2015-5874",
    "CVE-2015-5920"
  );
  script_bugtraq_id(
    42811,
    72288,
    74457,
    74523,
    74525,
    75491,
    76338,
    76343,
    76763,
    76764,
    76765,
    76766
  );
  script_osvdb_id(
    67674,
    127594,
    127606,
    127607,
    127608,
    127611,
    127613,
    127614,
    127615,
    127616,
    127617,
    127618,
    127630,
    127652,
    127653,
    127654,
    127655,
    127656,
    127657,
    127658,
    127659,
    127660,
    127661,
    127662,
    127663,
    127664,
    127665,
    127666,
    127667,
    127668,
    127669,
    127670,
    127671,
    127672,
    127673,
    127674,
    127675,
    127676
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-09-16-3");
  script_xref(name:"IAVB", value:"2011-B-0046");

  script_name(english:"Apple iTunes < 12.3 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of iTunes on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
prior to 12.3. It is, therefore, affected by multiple vulnerabilities
in the bundled versions of WebKit, CoreText, the Microsoft Visual
Studio C++ Redistributable Package, and ICU.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205221");
  # https://lists.apple.com/archives/security-announce/2015/Sep/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb0bd3a7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes 12.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

fixed_version = "12.3.0.44";
if (ver_compare(ver:version, fix:fixed_version) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "iTunes", version, path);

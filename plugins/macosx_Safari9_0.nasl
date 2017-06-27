#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86252);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id(
    "CVE-2015-3801",
    "CVE-2015-5764",
    "CVE-2015-5765",
    "CVE-2015-5767",
    "CVE-2015-5780",
    "CVE-2015-5788",
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
    "CVE-2015-5820",
    "CVE-2015-5821",
    "CVE-2015-5822",
    "CVE-2015-5823",
    "CVE-2015-5825",
    "CVE-2015-5826",
    "CVE-2015-5827",
    "CVE-2015-5828"
  );
  script_bugtraq_id(76764);
  script_osvdb_id(
    127589,
    127606,
    127607,
    127608,
    127613,
    127614,
    127615,
    127616,
    127617,
    127618,
    127637,
    127638,
    127639,
    127651,
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
    127676,
    127677,
    127680,
    127681,
    127683,
    128272,
    128273
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-09-30-2");

  script_name(english:"Mac OS X : Apple Safari < 9.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X host is
prior to 9.0. It is, therefore, affected by multiple vulnerabilities
in the following components :

  - Safari
  - Safari Downloads
  - Safari Extensions
  - Safari Safe Browsing
  - WebKit
  - WebKit CSS
  - WebKit JavaScript Bindings
  - WebKit Page Loading
  - WebKit Plug-ins");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205265");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 9.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");

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

get_kb_item_or_exit("MacOSX/Safari/Installed");
path    = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "9.0";

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

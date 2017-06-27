#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83291);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id(
    "CVE-2015-1152",
    "CVE-2015-1153",
    "CVE-2015-1154",
    "CVE-2015-1155",
    "CVE-2015-1156"
  );
  script_bugtraq_id(
    74523,
    74524,
    74525,
    74526,
    74527
  );
  script_osvdb_id(
    121738,
    121739,
    121740,
    121741,
    121742
  );

  script_name(english:"Mac OS X : Apple Safari < 6.2.6 / 7.1.6 / 8.0.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X host is
prior to 6.2.6 / 7.1.6 / 8.0.6. It is, therefore, affected by the
following vulnerabilities :

  - Multiple memory corruption issues in WebKit due to
    improper validation of user-supplied input. A remote
    attacker can exploit this, via a specially crafted
    web page, to cause a denial of service condition or to
    execute arbitrary code. (CVE-2015-1152, CVE-2015-1153,
    and CVE-2015-1154)

  - An information disclosure vulnerability in WebKit
    History exists due to a state management flaw and
    improper validation of user-supplied input. A remote
    attacker can exploit this, via a specially crafted web
    page, to disclose sensitive information from the file
    system. (CVE-2015-1155)
    
  - A flaw exists in WebKit Page Loading due to improper
    handling of rel attributes in anchor elements that
    allows target objects to get unauthorized access to link
    objects. A remote attacker can exploit this, via a
    specially crafted web page, to spoof the user interface.
    (CVE-2015-1156)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT204826");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari 6.2.6 / 7.1.6 / 8.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/08");

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

if (!ereg(pattern:"Mac OS X 10\.([89]|10)([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.8 / 10.9 / 10.10");

get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

if ("10.8" >< os)
  fixed_version = "6.2.6";
else if ("10.9" >< os)
  fixed_version = "7.1.6";
else
  fixed_version = "8.0.6";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
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

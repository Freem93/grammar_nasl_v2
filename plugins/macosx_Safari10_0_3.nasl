#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96798);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/30 15:10:03 $");

  script_cve_id(
    "CVE-2017-2350",
    "CVE-2017-2354",
    "CVE-2017-2355",
    "CVE-2017-2356",
    "CVE-2017-2359",
    "CVE-2017-2362",
    "CVE-2017-2363",
    "CVE-2017-2364",
    "CVE-2017-2365",
    "CVE-2017-2366",
    "CVE-2017-2369",
    "CVE-2017-2373"
  );
  script_bugtraq_id(
    95724,
    95725,
    95727,
    95728,
    95733,
    95736
  );
  script_osvdb_id(
    150756,
    150765,
    150766,
    150767,
    150768,
    150769,
    150770,
    150771,
    150772,
    150773,
    150774,
    150776
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-01-23-5");

  script_name(english:"macOS : Apple Safari < 10.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote macOS or Mac OS X 
host is prior to 10.0.3. It is, therefore, affected by multiple
vulnerabilities :

  - A prototype access flaw exists in WebKit when handling
    exceptions. An unauthenticated, remote attacker can
    exploit this, via specially crafted web content, to
    disclose cross-origin data. (CVE-2017-2350)

  - Multiple memory corruption issues exist in WebKit due to
    improper validation of certain unspecified input. An
    unauthenticated, remote attacker can exploit these, via
    specially crafted web content, to corrupt memory,
    resulting in the execution of arbitrary code.
    (CVE-2017-2354, CVE-2017-2356, CVE-2017-2362,
    CVE-2017-2366, CVE-2017-2369, CVE-2017-2373)

  - An unspecified memory initialization flaw exists in
    WebKit that allows an unauthenticated, remote attacker
    to execute arbitrary code. (CVE-2017-2355)

  - An unspecified state management flaw exists that allows
    an unauthenticated, remote attacker to spoof the address
    bar. (CVE-2017-2359)

  - Multiple flaws exist in WebKit when handling page
    loading due to improper validation of certain
    unspecified input. An unauthenticated, remote attacker
    can exploit these, via specially crafted web content, to
    disclose cross-origin data. (CVE-2017-2363,
    CVE-2017-2364)

  - A flaw exists in WebKit when handling variables due to
    improper validation of certain unspecified input. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted web content, to disclose cross-origin
    data. (CVE-2017-2365)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207484");
  # https://lists.apple.com/archives/security-announce/2017/Jan/msg00006.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35df638b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 10.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X or macOS");

if (!ereg(pattern:"Mac OS X 10\.(10|11|12)([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X Yosemite 10.10 / Mac OS X El Capitan 10.11 / macOS Sierra 10.12");

installed = get_kb_item_or_exit("MacOSX/Safari/Installed", exit_code:0);
path      = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version   = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "10.0.3";

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

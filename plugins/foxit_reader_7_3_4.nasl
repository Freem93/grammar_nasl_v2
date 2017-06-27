#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90567);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_cve_id(
    "CVE-2016-4059",
    "CVE-2016-4060",
    "CVE-2016-4061",
    "CVE-2016-4062",
    "CVE-2016-4063",
    "CVE-2016-4064",
    "CVE-2016-4065",
    "CVE-2016-4065"
  );
  script_osvdb_id(
    136000, 
    136001, 
    136002, 
    136003, 
    136004, 
    136005, 
    136006, 
    136007, 
    136008, 
    136251, 
    136252
  );
  script_xref(name:"ZDI", value:"ZDI-16-211");
  script_xref(name:"ZDI", value:"ZDI-16-212");
  script_xref(name:"ZDI", value:"ZDI-16-213");
  script_xref(name:"ZDI", value:"ZDI-16-214");
  script_xref(name:"ZDI", value:"ZDI-16-216");
  script_xref(name:"ZDI", value:"ZDI-16-215");
  script_xref(name:"ZDI", value:"ZDI-16-217");
  script_xref(name:"ZDI", value:"ZDI-16-218");
  script_xref(name:"ZDI", value:"ZDI-16-219");
  script_xref(name:"ZDI", value:"ZDI-16-220");
  script_xref(name:"ZDI", value:"ZDI-16-221");
  script_xref(name:"ZDI", value:"ZDI-16-222");

  script_name(english:"Foxit Reader < 7.3.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit Reader.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",  value:
"The version of Foxit Reader installed on the remote Windows host is
prior to 7.3.4. It is, therefore, affected by multiple
vulnerabilities :

  - A use-after-free error exists that is triggered when
    handling FlateDecode streams. An unauthenticated,
    remote attacker can exploit this, via a crafted PDF
    file, to dereference already freed memory, resulting in
    a denial of service or the execution of arbitrary code.
    (CVE-2016-4059)

  - A use-after-free error exists that is related to the
    TimeOut() function. An unauthenticated, remote attacker
    can exploit this, via a crafted PDF file, to dereference
    already freed memory, resulting in a denial of service
    or the execution of arbitrary code. (CVE-2016-4060)

  - An unspecified flaw exists that is triggered when
    parsing content streams. An unauthenticated, remote
    attacker can exploit this to crash the application,
    resulting in a denial of service. (CVE-2016-4061)

  - An unspecified flaw exists that is triggered when
    recursively triggering PDF format errors. An
    unauthenticated, remote attacker can exploit this to
    cause the application to stop responding, resulting in a
    denial of service. (CVE-2016-4062)

  - A use-after-free error exists that is triggered when
    handling object revision numbers. An unauthenticated,
    remote attacker can exploit this, via a crafted PDF
    file, to dereference already freed memory, resulting in
    a denial of service or the execution of arbitrary code.
    (CVE-2016-4063)

  - A use-after-free error exists that is triggered when
    handling XFA re-layouts. An unauthenticated, remote
    attacker can exploit this to dereference already freed
    memory, resulting in a denial of service or the
    execution of arbitrary code. (CVE-2016-4064)

  - An out-of-bounds read error exists that is triggered
    when decoding BMP, GIF, and JPEG images during PDF
    conversion. An unauthenticated, remote attacker can
    exploit this to disclose sensitive memory contents or
    cause a denial of service. (CVE-2016-4065)

  - An unspecified use-after-free error exists that allows
    an unauthenticated, remote attacker to dereference
    already freed memory, resulting in a denial of service
    or the execution of arbitrary code. (VulnDB 136000)

  - A use-after-free error exists that is triggered when
    handling JavaScript API calls when closing a document.
    An unauthenticated, remote attacker can exploit this,
    via a crafted PDF file, to dereference already freed
    memory, resulting in a denial of service or the
    execution of arbitrary code. (VulnDB 136006)");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-211/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-212/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-213/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-214/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-215/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-216/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-217/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-218/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-219/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-220/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-221/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-222/");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 7.3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Foxit Reader";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install["version"];
path    = install["path"];

report = NULL;

fixed_version = "7.3.4";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port)
    port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version + '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);


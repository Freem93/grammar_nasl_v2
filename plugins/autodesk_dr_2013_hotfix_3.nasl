#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96315);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/11 15:18:39 $");

  script_bugtraq_id(95089);
  script_osvdb_id(
    149398,
    149399,
    149400,
    149401,
    149402,
    149403
  );
  script_xref(name:"ZDI", value:"ZDI-16-664");
  script_xref(name:"ZDI", value:"ZDI-16-665");
  script_xref(name:"ZDI", value:"ZDI-16-666");
  script_xref(name:"ZDI", value:"ZDI-16-667");
  script_xref(name:"ZDI", value:"ZDI-16-668");
  script_xref(name:"ZDI", value:"ZDI-16-669");
  script_xref(name:"IAVA", value:"2017-A-0001");

  script_name(english:"Autodesk Design Review < 2013 Hotfix 3 Multiple RCE");
  script_summary(english:"Checks the version of Autodesk Design Review.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Autodesk Design Review installed on the remote Windows
host is prior to 2013 Hotfix 3. It is, therefore, affected by the
following vulnerabilities :

  - A buffer overflow condition exists when handling FLI
    files due to improper validation of user-supplied input.
    An unauthenticated, remote attacker can exploit this to
    execute arbitrary code by convincing a user to visit a
    malicious web page or open a specially crafted file.
    (VulnDB 149398)

  - A buffer overflow condition exists when handling BMP
    files due to improper validation of the size of the
    biClrUsed field. An unauthenticated, remote attacker can
    exploit this to execute arbitrary code by convincing a
    user to visit a malicious web page or open a specially
    crafted file. (VulnDB 149399)

  - A use-after-free error exists when handling PNG files.
    An unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a malicious web page or open
    a specially crafted file, to dereference already freed
    memory, resulting in the execution of arbitrary code.
    (VulnDB 149400)

  - A buffer overflow condition exists when handling JFIF
    files due to a failure to ensure that decompressed
    content fits within an allocated buffer. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code by convincing a user to visit a
    malicious web page or open a specially crafted file.
    (VulnDB 149401)

  - An out-of-bounds indexing error exists when handling
    JPEG files that allows an unauthenticated, remote
    attacker to execute arbitrary code by convincing a user
    to visit a malicious web page or open a specially
    crafted file. (VulnDB 149402)

  - An out-of-bounds indexing error exists when handling
    GIF files that allows an unauthenticated, remote
    attacker to execute arbitrary code by convincing a user
    to visit a malicious web page or open a specially
    crafted file. (VulnDB 149403)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-664/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-665/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-666/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-667/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-668/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-669/");
  # http://knowledge.autodesk.com/support/design-review/downloads/caas/downloads/content/autodesk-design-review-2013-hotfix.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d427536b");
  script_set_attribute(attribute:"solution", value:
"Apply Hotfix 3 to Autodesk Design Review 2013.

Note that older versions will first need to be upgraded to Autodesk
Design Review 2013 before applying the hotfix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:design_review");
  script_set_attribute(attribute:"stig_severity", value:"II");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "autodesk_dr_installed.nbin");
  script_require_keys("installed_sw/Autodesk Design Review");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");

app = "Autodesk Design Review";

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

fixed = '13.3.0.82';

if (ver_compare(ver:version, fix:fixed, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  order = make_list("Installed version", "Fixed version", "Path");
  report = make_array(
    order[0], version,
    order[1], fixed,
    order[2], path
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, path, version);

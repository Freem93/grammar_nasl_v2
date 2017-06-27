#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76357);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/11 13:32:17 $");

  script_cve_id("CVE-2014-0224");
  script_bugtraq_id(67899);
  script_osvdb_id(107729);
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"HP", value:"HPSBMU03058");
  script_xref(name:"IAVB", value:"2014-B-0084");

  script_name(english:"HP Onboard Administrator < 4.22 Remote Information Disclosure");
  script_summary(english:"Checks the version of HP Onboard Administrator.");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by a remote information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP Onboard Administrator installed on the remote host
is prior to 4.22. It is, therefore, affected by the following OpenSSL
related vulnerability :

  - An unspecified error exists that could allow an
    attacker to cause usage of weak keying material
    leading to simplified man-in-the-middle attacks.
    (CVE-2014-0224)");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c04351097
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7496652c");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 4.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:onboard_administrator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_onboard_admin_detect.nasl");
  script_require_keys("Host/HP/Onboard_Administrator");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item_or_exit(
  "Host/HP/Onboard_Administrator/Port",
  exit_code : 1,
  msg       : "Unable to get the HP Onboard Administrator Port."
);

version = get_kb_item_or_exit(
  "Host/HP/Onboard_Administrator/Version",
  exit_code : 1,
  msg       : "Unable to get the HP Onboard Administrator Version."
);

fix = "4.22";

if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0) audit(AUDIT_HOST_NOT, "affected");

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';
}
security_warning(port:port, extra:report);

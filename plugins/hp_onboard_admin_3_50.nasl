#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70141);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/08 22:17:25 $");

  script_cve_id("CVE-2012-0128", "CVE-2012-0129", "CVE-2012-0130");
  script_bugtraq_id(52862);
  script_osvdb_id(80883, 80884, 80885);

  script_name(english:"HP Onboard Administrator Multiple Vulnerabilities");
  script_summary(english:"Check KB.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server is a version of HP Onboard Administrator (OA)
that is affected by the following vulnerabilities :

  - HP Onboard Administrator before 3.50 allows remote
    attackers to obtain sensitive information via
    unspecified vectors. (CVE-2012-0130)

  - HP Onboard Administrator before 3.50 allows remote
    attackers to bypass intended access restrictions and
    execute arbitrary code via unspecified vectors.
    (CVE-2012-0129)

  - HP Onboard Administrator before 3.50 allows remote
    attackers to redirect users to arbitrary websites and
    conduct phishing attacks via unspecified vectors.
    (CVE-2012-0128)"
  );
  #http://h20000.www2.hp.com/bizsupport/TechSupport/SoftwareIndex.jsp?lang=en&cc=us&prodNameId=3188475&prodTypeId=329290&prodSeriesId=3188465&swLang=8&taskId=135&swEnvOID=1113
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9794c7b");
  #http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03263573
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?033b8115");

  script_set_attribute(attribute:"solution", value:"Upgrade to HP Onboard Administrator 3.50 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:onboard_administrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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

fix = "3.50";

if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0) audit(AUDIT_HOST_NOT, "affected");

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';
}
security_hole(port:port, extra:report);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74287);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/13 20:51:05 $");

  script_cve_id("CVE-2014-0076", "CVE-2014-0963");
  script_bugtraq_id(66363, 67238);
  script_osvdb_id(104810, 106786);

  script_name(english:"IBM Global Security Kit 7 < 7.0.4.50 / 8.0.14.x < 8.0.14.43 / 8.0.50.x < 8.0.50.20 Multiple Vulnerabilities");
  script_summary(english:"Checks GSKit version");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a library installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of IBM Global Security Kit prior
to 7.0.4.50 / 8.0.14.43 / 8.0.50.20. It is, therefore, affected by the
following vulnerabilities :

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

  - A denial of service vulnerability exists which an
    attacker can exploit by sending a specially crafted SSL
    request to cause the host to become unresponsive.
    (CVE-2014-0963)");
  # Tivoli Access Manager for e-Business
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672189");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672950");
  # HTTP Server
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21672843");
  # Rational ClearCase
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21671919");
  # Rational ClearQuest
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673521");
  # Websphere Application Server
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21672843");
  # WebSphere Portal
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673682");
  # Business Process Manager (BPM)
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672192");
  # WebSphere Dynamic Process Edition
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21673749");
  # Business Services Fabric
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21673745");
  # Rational RequisitePro
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673418");
  # DB2
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21671732");
  # Security Network Intrusion Prevention System (Proventia)
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673282");
  # Security Access Manager for Web
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672192");
  # Rational Developer
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21673259");
  # Tivoli Workload Scheduler
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673696");
  # WebSphere Voice Response
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673245");
  # Tivoli Netcool Service Quality Manager
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21673689");
  # WebSphere Transformation Extender Secure Adapter Collection 8.4.1.1
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673600");
  # Content Manager OnDemand for Multiplatform
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672869");
  # Content Manager Enterprise Edition
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673717");
  # SPSS Modeler
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21673666");
  # Informix Server
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21673008");
  # Security Directory Server
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672724");
  # Content Collector for SAP Applications V3.0
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673040");
  script_set_attribute(attribute:"solution", value:
"Apply GSKit 7.0.4.50 / 8.0.14.43 / 8.0.50.20 or later or apply the
appropriate patch referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:global_security_kit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("ibm_gskit_installed.nasl");
  script_require_keys("installed_sw/IBM GSKit", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (!get_kb_item("SMB/Registry/Enumerated")) audit(AUDIT_OS_NOT, "Windows", "Linux");

app = "IBM GSKit";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];
fix = NULL;

if (version =~ '^7\\.0\\.' && ver_compare(ver:version, fix:'7.0.4.50') < 0)
  fix = '7.0.4.50';
else if (version =~ '^8\\.0\\.14\\.' && ver_compare(ver:version, fix:'8.0.14.43') < 0)
  fix = '8.0.14.43';
else if (version =~ '^8\\.0\\.50\\.' && ver_compare(ver:version, fix:'8.0.50.20') < 0)
  fix = '8.0.50.20';
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

port = get_kb_item('SMB/transport');
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix + '\n';

  security_hole(port:port, extra:report);
}
else security_hole(port);

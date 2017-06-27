#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70126);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/08 20:12:55 $");

  script_cve_id("CVE-2012-3314");
  script_bugtraq_id(55732);
  script_osvdb_id(85866);

  script_name(english:"IBM Tivoli Federated Identity Manager XML Signature Validation Bypass");
  script_summary(english:"Checks the version of IBM Tivoli Federated Identity Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a
signature validation bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Tivoli Federated Identity Manager installed on the
remote Windows host is affected by a signature validation bypass
vulnerability due to improper validation of XML signatures related to
certain single sign-on protocols and token modules. A remote,
unauthenticated attacker can exploit this, via a specially crafted
message, to perform actions as another user.");
  # original source bulletin is missing, http://www-01.ibm.com/support/docview.wss?uid=swg21612612
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_tivoli_federated_identity_manager_multiple_protocol_xml_signature_validation_bypass_cve_2012_33143?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c13e74e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tivoli Federated Identity Manager 6.1.1.13 / 6.2.0.11 /
6.2.1.3 / 6.2.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_federated_identity_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("tivoli_federated_identity_manager_installed.nbin");
  script_require_keys("installed_sw/IBM Tivoli Federated Identity Manager");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include("install_func.inc");

app_name = 'IBM Tivoli Federated Identity Manager';
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

version = install['version'];
path    = install['path'];

fix = '';
if (version =~ '^6\\.1\\.1($|\\.)' && ver_compare(ver:version, fix:'6.1.1.13', strict:FALSE) < 0) fix = '6.1.1.13';
else if (version =~ '^6\\.2\\.0($|\\.)' && ver_compare(ver:version, fix:'6.2.0.11', strict:FALSE) < 0) fix = '6.2.0.11';
else if (version =~ '^6\\.2\\.1($|\\.)' && ver_compare(ver:version, fix:'6.2.1.3', strict:FALSE) < 0) fix = '6.2.1.3';
else if (version =~ '^6\\.2\\.2($|\\.)' && ver_compare(ver:version, fix:'6.2.2.2', strict:FALSE) < 0) fix = '6.2.2.2';
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

port = get_kb_item("SMB/transport");
if(isnull(port)) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);

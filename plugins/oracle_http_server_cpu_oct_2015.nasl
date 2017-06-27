#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86569);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/04/24 18:58:37 $");

  script_cve_id(
    "CVE-2014-0191",
    "CVE-2015-1829",
    "CVE-2015-4812",
    "CVE-2015-4914"
  );
  script_bugtraq_id(
    67233,
    75164,
    77195,
    77201
  );
  script_osvdb_id(
    106710,
    121515,
    129082,
    129083
  );

  script_name(english:"Oracle Fusion Middleware Oracle HTTP Server Multiple Vulnerabilities (October 2015 CPU)");
  script_summary(english:"Checks the version of Oracle HTTP Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host is
affected by multiple vulnerabilities :

  - A denial of service vulnerability exists in libxml2,
    related to the xmlParserHandlePEReference() function in
    file parser.c, due to loading external parameter
    entities without regard to entity substitution or
    validation being enabled, as in the case of entity
    substitution in the doctype prolog. An unauthenticated,
    remote attacker can exploit this, via specially crafted
    XML content, to exhaust the system CPU, memory, or file
    descriptor resources. (CVE-2014-0191)

  - An unspecified vulnerability exists in the Web Listener
    component that allows an unauthenticated, remote
    attacker to impact availability. (CVE-2015-1829)

  - An unspecified vulnerability exists in the OSSL Module
    that allows an unauthenticated, remote attacker to
    impact confidentiality. (CVE-2015-4812)

  - An unspecified vulnerability exists in the Web Listener
    component that allows an authenticated, remote attacker
    to impact confidentiality. (CVE-2015-4914)");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a4a4fb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("Oracle/OHS/Installed");
installs = get_kb_list_or_exit("Oracle/OHS/*/Version");

patches = make_array();
patches['10.1.3.5'] = make_list('21845960','21845962','21845971');
patches['11.1.1.7'] = make_list('21640624');
patches['11.1.1.9'] = make_list('21640624','21663064', '23623015');
patches['12.1.2.0'] = make_list('17621876','19485397','21768251','21773977');
patches['12.1.3.0'] = make_list('19485414','21640673','22557350');

oracle_product_check_vuln(
  product  : 'Oracle HTTP Server',
  installs : installs,
  kbprefix : 'Oracle/OHS/',
  patches  : patches
);

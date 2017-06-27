#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92542);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/07/27 13:35:33 $");

  script_cve_id("CVE-2016-3482");
  script_bugtraq_id(92026);
  script_osvdb_id(141760);

  script_name(english:"Oracle Fusion Middleware Oracle HTTP Server Information Disclosure (July 2016 CPU)");
  script_summary(english:"Checks the version of Oracle HTTP Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host is
affected by an information disclosure vulnerability in the SSL/TLS
Module subcomponent. An unauthenticated, remote attacker can exploit
this to disclose sensitive information.");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e49b75d6");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2016 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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
patches['11.1.1.9'] = make_list('23623015');
patches['12.1.3.0'] = make_list('22557350');

# security warning
oracle_product_check_vuln(
  product  : 'Oracle HTTP Server',
  installs : installs,
  kbprefix : 'Oracle/OHS/',
  patches  : patches
);

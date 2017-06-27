#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76132);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2014-0224", "CVE-2014-3470");
  script_bugtraq_id(67898, 67899);
  script_osvdb_id(107729, 107731);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Cisco TelePresence Supervisor MSE 8050 Multiple Vulnerabilities in OpenSSL");
  script_summary(english:"Checks TelePresence Supervisor version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco TelePresence device is running a software version
known to be affected by multiple OpenSSL related vulnerabilities :

  - An unspecified error exists that could allow an
    attacker to cause usage of weak keying material
    leading to simplified man-in-the-middle attacks.
    (CVE-2014-0224)

  - An unspecified error exists related to anonymous ECDH
    ciphersuites that could allow denial of service
    attacks. Note this issue only affects OpenSSL TLS
    clients. (CVE-2014-3470)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140605-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5539aa9d");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:"There is currently no known solution.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_supervisor_mse_8050");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_supervisor_mse_detect.nbin");
  script_require_keys("cisco/supervisor_mse/8050");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("cisco/supervisor_mse/8050");

item = eregmatch(pattern: "^([0-9.]+)(\(([0-9.]+)\))?$", string: version);
if (isnull(item)) exit(1, "Failed to parse version string.");

if (isnull(item[3])) audit(AUDIT_VER_NOT_GRANULAR, "Cisco TelePresence Supervisor MSE 8050", version);

vuln = FALSE;

if (item[1] == "2.1" && item[3] == "1.18")
  vuln = TRUE;

if (item[1] == "2.2" && item[3] == "1.17")
  vuln = TRUE;

if (item[1] == "2.3" && item[3] == "1.31")
  vuln = TRUE;

if (item[1] == "2.3" && item[3] == "1.32")
  vuln = TRUE;

if (vuln) security_warning(0);
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco TelePresence Supervisor MSE 8050 software", version);

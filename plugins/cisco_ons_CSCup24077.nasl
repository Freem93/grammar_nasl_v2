#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76130);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2014-0076", "CVE-2014-3470");
  script_bugtraq_id(66363, 67898);
  script_osvdb_id(104810, 107731);

  script_name(english:"Cisco ONS 15400 Series Devices Multiple Vulnerabilities in OpenSSL");
  script_summary(english:"Checks device version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco ONS device is running a software version known to be
affected by multiple OpenSSL related vulnerabilities :

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

  - An unspecified error exists related to anonymous ECDH
    ciphersuites that could allow denial of service
    attacks. Note this issue only affects OpenSSL TLS
    clients. (CVE-2014-3470)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140605-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5539aa9d");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:
"No known fixed version have been released. There are partial
workarounds detailed in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ons");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ons_detect.nasl");
  script_require_keys("Cisco/ONS/Device", "Cisco/ONS/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

device = get_kb_item_or_exit("Cisco/ONS/Device");
version = get_kb_item_or_exit("Cisco/ONS/Version");

report = '';

if (device =~ "^15454")
{
  item = eregmatch(pattern: "^([0-9.]+)-", string:version);
  if (isnull(item)) exit(1, "Error parsing version string.");

  # nb: strip leading zeros
  int_version = eregmatch(pattern:"^0*([1-9][0-9]*)\.([0-9])([0-9])([0-9])?$", string:item[1]);

  if (max_index(int_version) < 4 || isnull(int_version)) exit(1, "Error parsing version string.");

  formatted_ver = join(make_list(int_version[1], int_version[2], int_version[3]), sep:'.');
  if (max_index(int_version) > 4) formatted_ver += "." + int_version[4];

  if (
    formatted_ver == "9.8.0" || 
    formatted_ver == "9.8.1.1" ||
    formatted_ver == "10.0.0" || 
    formatted_ver == "10.0.1"
  )
  {
    report = '\n  Installed version : ' + formatted_ver + ' (' + version + ')' +
             '\n';
  }
}
else exit(0, "The remote Cisco ONS Device is not affected.");

if (report != '')
{
  if (report_verbosity > 0) security_warning(port:0, extra:report);
  else security_warning(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ONS", version);

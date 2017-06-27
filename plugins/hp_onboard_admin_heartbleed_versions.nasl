#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76509);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"HP", value:"emr_na-c04236062");
  script_xref(name:"HP", value:"HPSBMU02994");

  script_name(english:"HP BladeSystem c-Class Onboard Administrator 4.11 / 4.20 Heartbeat Information Disclosure (Heartbleed)");
  script_summary(english:"Version check for HP BladeSystem c-Class Onboard Administrator.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has version 4.11 or 4.20 of HP BladeSystem c-Class
Onboard Administrator. It is, therefore, affected by an out-of-bounds
read error, known as the 'Heartbleed Bug' in the included OpenSSL
version.

This error is related to handling TLS heartbeat extensions that could
allow an attacker to obtain sensitive information such as primary key
material, secondary key material, and other protected content. Note
this affects both client and server modes of operation.");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04236062
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f18ac6e4");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:"Update to firmware version 4.12 / 4.21.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:onboard_administrator");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
  msg       : "Failed to get the HP Onboard Administrator port."
);

version = get_kb_item_or_exit(
  "Host/HP/Onboard_Administrator/Version",
  exit_code : 1,
  msg       : "Failed to get the HP Onboard Administrator version."
);

# nb: this only affects HP BladeSystem c-Class Onboard Administrator (OA) v4.11 and v4.20
if (version == "4.11") fixed_version = "4.12";
else if (version == "4.20") fixed_version = "4.21";
else audit(AUDIT_INST_VER_NOT_VULN, "HP BladeSystem c-Class Onboard Administrator", version);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);


#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74010);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/19 17:45:33 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo16472");

  script_name(english:"Cisco TelePresence Video Communication Server Heartbeat Information Disclosure (Heartbleed)");
  script_summary(english:"Checks software version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Cisco TelePresence Video Communication Server installed
on the remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Cisco
TelePresence Video Communication Server installed on the remote host
is affected by an out-of-bounds read error, known as the 'Heartbleed
Bug' in the included OpenSSL version.

This error is related to handling TLS heartbeat extensions that could
allow an attacker to obtain sensitive information such as primary key
material, secondary key material, and other protected content. Note
this affects both client and server modes of operation.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140409-heartbleed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f211d28");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuo16472");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 7.2.3 / 8.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

prod = "Cisco TelePresence Video Communication Server";
version = get_kb_item_or_exit("Cisco/TelePresence_VCS/Version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version !~ "^7\.2($|\.)" && version != "8.1") audit(AUDIT_INST_VER_NOT_VULN, prod, version);

note = "";

if (version =~ "^7\.2($|\.)")
{
  fix = "7.2.3";
  note = '\n' +
         '\n' + 'Note: Users running the non-AES versions of 7.2, 7.2.1, and 7.2.2' +
         '\n' + 'are NOT affected by this issue, while those running 7.2.3 RC2 are.' +
         '\n' + 'Refer to the vendor\'s advisory for details.';
}
else if (version == "8.1")
{
  fix = "8.1.1";
}

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fix +
             note + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, prod, version);
